# wmic_server
# server for running wmi queries using aiowmi

# generic imports
from flask import Flask, jsonify, request, make_response
# from flask_restful import Resource, Api
import time
import io
import os
import re
import asyncio
import json
import sys
import yaml
from datetime import datetime, timedelta

# now we can import the aiowmi code since we should now have this in our path
from aiowmi.connection import Connection
from aiowmi.query import Query
from aiowmi.exceptions import WbemFalse
from aiowmi.tools import dt_fmt

# ==================================== INIT ==================================


# work out the current directory where this script is running from
from pathlib import Path
working_dir = Path(__file__).absolute().parent

# some environment variables are passed
config_file = \
    os.getenv('WMIC_SERVER_CONFIG', str(working_dir) + '/wmic_server.yaml')
listen_port = os.getenv('WMIC_SERVER_PORT', '2313')
listen_address = os.getenv('WMIC_SERVER_ADDRESS', '127.0.0.1')
debug = os.getenv('WMIC_SERVER_DEBUG', '')

# open the config file
with open(config_file, "r") as file:
    try:
        cfg = yaml.load(file, Loader=yaml.FullLoader)
        debug and print("YAML configuration is:")
        debug and print(cfg)
    except yaml.YAMLError as exc:
        print("YAML configuration error")
        print(exc)
        quit()

app = Flask(__name__)

# open the stdout file descriptor in write mode and
# set 0 as the buffer size: unbuffered
try:
    # open stdout in binary mode,
    # then wrap it in a TextIOWrapper and enable write_through
    # please make sure that the "write_" at the start of the wrapped line
    # sits exactly in that column otherwise it will not meet PEP8 standard
    # since one more column to the right makes it over indented
    # and one more column to the left makes it under indented
    sys.stdout = io.TextIOWrapper(open(sys.stdout.fileno(), 'wb', 0),
                                  write_through=True)
    # above line must start at    X

    # for flushing on newlines only use :
    # sys.stdout.reconfigure(line_buffering = True)
except TypeError:
    # In case you are on Python 2
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

# ==================================== FUNCTIONS ==============================


# -------------------------------------------------------------------------
def encode_value(value):
    if isinstance(value, datetime):
        # you need to choose some JSON compatible datetime conversion
        # if you want to return a native python value then
        #   return value.isoformat()
        return dt_fmt(value)
    if isinstance(value, timedelta):
        # you need to choose some JSON compatible timedelta conversion
        return value.microseconds
    return value


# -------------------------------------------------------------------------
async def get_json_output(query, conn, service):
    result = []
    async with query.context(conn, service) as qc:
        async for props in qc.results(ignore_defaults=False):
            # get the properties using ignore_defaults
            # to convert integer null values to 0
            item = {
                name: encode_value(prop.value)
                for name, prop in props.items()
            }
            result.append(item)

    return json.dumps(result)


# -------------------------------------------------------------------------
def validate_input(method, param_name, default_value, regex_list):
    global debug
    # pass in
    # the input string to validate
    # a list of regular expressions to check for validity
    if method == 'GET':
        param_value = request.args.get(param_name, default_value)
    elif method == 'POST':
        param_value = request.json.get(param_name, default_value)

    debug and print("Checking " + param_name + " = " + param_value)
    try:
        for regex in regex_list:
            if re.search(regex, param_value, flags=re.IGNORECASE) is not None:
                # found a valid match
                debug and print(param_name + " = " + param_value
                                + " matches regex " + regex)
                return param_value
    except Exception:
        return param_value

    return ""


# -------------------------------------------------------------------------
@app.route('/wmic', methods=['GET', 'POST'])
def wmic():
    # simply run the aiowmi code and return the output
    return asyncio.run(wmic_core())


# -------------------------------------------------------------------------
async def wmic_core():
    global debug

    # load the parameters from the request
    # or set them to default value if not present
    id = validate_input(request.method, 'id', '', cfg['validation']['id'])
    token = \
        validate_input(request.method, 'token', '', cfg['validation']['token'])
    host = \
        validate_input(request.method, 'host', '', cfg['validation']['host'])

    # please make sure that the "cfg" at the start of the wrapped line
    # sits exactly in that column otherwise it will not meet PEP8 standard
    # since one more column to the right makes it over indented
    # and one more column to the left makes it under indented
    query_input = validate_input(request.method, 'query', '',
                                 cfg['validation']['query'])
    # above line must start at   X

    # namespace defaulting to root/cimv2
    # please make sure that the "'root/" at the start of the wrapped line
    # sits exactly in that column otherwise it will not meet PEP8 standard
    # since one more column to the right makes it over indented
    # and one more column to the left makes it under indented
    namespace = validate_input(request.method, 'namespace',
                               'root/cimv2', cfg['validation']['namespace'])
    # above line must start at X

    # flag to tell us if the http call contains a valid token
    valid_token = False

    # sorry, I have to use poor english to make this next comment fit
    # the arbitrary line length limiations
    # flag to tell us if we are using token auth ie there is some tokens define
    token_auth = False

    # try and access generic tokens (if there are any defined)
    try:
        # now see if the token is one of the valid tokens in our config list
        if token in cfg['tokens']:
            debug and print("valid generic token:", token)
            valid_token = True
            token_auth = True
        else:
            token_auth = True
            debug and print("invalid generic token:", token)
    except Exception:
        debug and print("no generic tokens defined")

    # if there is still no valid token, try a id-specific token
    if not valid_token:
        try:
            # break up comment below to 2 lines since it is too long!
            # now see if the token is one of the
            # valid tokens in our config list for this id
            if token in cfg[id]['tokens']:
                debug and print("valid id specific token:", token)
                valid_token = True
                token_auth = True
            else:
                debug and print("invalid specific token:", token)
                token_auth = True
        except Exception:
            debug and print("no specific tokens defined")

    debug and print("Token_auth = ", token_auth)
    debug and print("Valid_token = ", valid_token)

    if (token_auth and valid_token) or (not token_auth):
        # load the user/pass out put the
        # yaml config file based off the id value passed
        username = cfg[id]["user"]
        password = cfg[id]["pass"]

        try:
            domain = cfg[id]["domain"]
        except Exception:
            debug and print("Domain not specified, setting to empty")
            domain = ''

        if domain is None:
            debug and print("Setting Domain to empty")
            domain = ''

        query = Query(query_input, namespace)

        if debug:
            print("User = " + username)
            print("Domain = " + domain)
            print("Query = " + query_input)

        service = None

        conn = Connection(host, username, password, domain=domain)
        try:
            await conn.connect()
        except Exception as error:
            # probably could not connect
            debug and print("Exception occurred in the wmi connection")
            debug and print(str(error))
            return "Problem with connection to target host. " + str(error)

        try:
            service = await conn.negotiate_ntlm()
            out = await get_json_output(query, conn, service)
            # print(out)  # print the JSON output
            return out
        except Exception as error:
            # probably could not connect
            debug and print("Exception occurred in the wmi query")
            debug and print(str(error))
            return "Problem with the wmi query on the target host. " \
                + str(error)
        finally:
            if service:
                service.close()
                conn.close()
    else:
        return "ERROR: Invalid token"


# ==================================== MAIN ==================================

if __name__ == '__main__':

    debug and print("Starting on " + listen_address + ":" + listen_port)
    app.run(port=listen_port, host=listen_address)

"""
# in the following examples you might want to take out the \
# and run it on one line for use cases where you have a modern screen

# in production
# gunicorn -b 127.0.0.1:2313 \
    --pythonpath PATH/aiowmi,PATH/contrib/wmic_server \
    --threads 1 wmic_server:app

# for development run like:
# PYTHONPATH = /opt/nagios/bin/plugins/aiowmi \
    FLASK_ENV = development \
    WMIC_SERVER_DEBUG = 1 \
    python /opt/nagios/bin/plugins/aiowmi/contrib/wmic_server/wmic_server.py

# optionally insert the following variables into the command line if needed:
# WMIC_SERVER_ADDRESS
# WMIC_SERVER_PORT
"""

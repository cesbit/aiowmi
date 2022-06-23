# WMIC Server

Python WMIC Server which accepts HTTP connections from clients and passes WMI queries to Windows targets.
Uses aiowmi to make the WMI calls. Uses the Flask framework for the server. Uses PyYAML to read the yaml configuration file.

## Requirements

The ```requirements.txt``` file specifies the current versions that this code was developed with. It may well run with older versions.

## Installation

Download the aiowmi project

```
cd PATH_TO_AIOWMI
git clone https://github.com/cesbit/aiowmi
```

## Configuration

### Server Config
Rename the included ``wmic_server.yaml.sample`` to ``wmic_server.yaml``. The server will look for this file in the same directory as the main python code ```wmic_server.py```

This file is fairly well documented in the comments.

The server sits in between a client wanting to perform WMI queries and the target host that will respond to the WMI queries, like this:

CLIENT ---> WMIC_SERVER ---> WMI_TARGET

There are 3 types of configuration in this server config file:

#### 1. WMI Target authentication information - for authenticating to the WMI target

Authentication between the server and the target is required, and configured by providing the authentication information user/pass/domain in the server configuration.
This target authentication is defined using an ID. The client refers to the ID in its call to the server and then the server uses the authentication information matching the ID to authenticate to the target

Each ID section in the config file can optionally contain a token. More on this in the next sections

#### 2. WMI Server authentication tokens - for authenticating to the WMI Server

Authentication between the client and the server is optional, and configured using tokens defined by the wmic server administrator.
These tokens are optional. If any of them are used they all allow any client using one of these tokens to use the WMI Server
If you want different tokens per calling ID, then you can configure tokens in the ID sections

#### 3. Input validation - for validating the formatting of the client information received by the server

These are regular expressions that are used to validate the format of each parameter that is passed to the WMI Server.
The default included configuration is probably ok, but you can customise it as required.

### Server Environment Variables
There are some environment variables which can be set if you need to change the default configuration:
* WMIC_SERVER_DEBUG - set this to "1" to show some debug information
* WMIC_SERVER_CONFIG - the full path of a config file that is not in the same directory as wmic_server.py

## Starting the Sever

NOTE: It is possible to run all the client to server communications over HTTPS. This is beyond the scope of this documentation. The methods vary depending on exactly how you run the server.

Referring to WMIC_SERVER_INSTALL_DIR as the directory which contains wmic_server.py
eg ```PATH_TO_AIOWMI/contrib/wmic_server```

### For Testing/Pre-Implementation
Start the WMIC Server from the command line using something like:
```PYTHONPATH=PATH_TO_AIOWMI FLASK_ENV=development WMIC_SERVER_DEBUG=1 python WMIC_SERVER_INSTALL_DIR/wmic_server/wmic_server.py```

The following environment variables provide some configurability for the server:
WMIC_SERVER_CONFIG


optionally insert the following variables into the command line if needed (and customise them as needed): 
```
WMIC_SERVER_ADDRESS=127.0.0.1
WMIC_SERVER_PORT=2313
```
### For Production

For example, using systemd and gunicorn, implement the included systemd service file: ```wmic_server.service```
Documentation about setting paths and other options is in the sample systemd service file.

## Testing the Server

You can send HTTP requests to the server using many different techniques. Both GET and POST are supported. The usage of GET will potentially log sensitive information in the client call (depending on exactly how you have configured the client and the server, and possibly the network in between)

The included script ```wmic_client.sh``` uses curl to generate a POST request. The script comes with usage message (run it with no parameters)

## Sample Usage

The included ```wmic_server.yaml.sample``` creates an identity referred to as "user1". The configuration specifies the Windows username and password for "user1". It also defines a couple of tokens (eg "MYSECRETUSERACCESSTOKEN1") that must be presented by the client to activate this identity.

We could query the current time on a host "host1" by

```wmic_client.sh -i user1 -t MYSECRETUSERACCESSTOKEN1 -h host1 -q 'SELECT * FROM Win32_UTCTime'```

When this script is run, curl is used to generated a POST request to the WMIC Server. The WMIC Server checks the token is valid, and sends the WMI query ("SELECT * FROM Win32_UTCTime") to "host1" using the username/password defined for "user1"

The response should be similar to the following:
```
HTTP/1.1 200 OK
Server: gunicorn
Date: Mon, 20 Jun 2022 06:32:44 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 148

[{"Year": 2022, "Month": 6, "Day": 20, "DayOfWeek": 1, "WeekInMonth": 4, "Quarter": 2, "Hour": 6, "Minute": 32, "Second": 44, "Milliseconds": null}]# 
```

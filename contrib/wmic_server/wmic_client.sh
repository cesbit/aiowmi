#!/bin/bash
# send a wmi query to the wmic_server

wmic_server_url=http://127.0.0.1:2313/wmic
namespace=root/cimv2

#--------------------------------------------------------------------------------
usage ()
{
cat << EOT
Usage: $0 -i ID -t TOKEN -h HOST -q QUERY [-n NAMESPACE] [-u URL] [-d]

where
ID       is the ID matching authentication info on the wmic_server
TOKEN    is the authentication token giving access to the wmic_server
HOST     is the host to send the WMI query to
QUERY    is the WMI query eg SELECT * FROM Win32_UTCTime
NAMESPACEis the WMI namespace (defaulting to $namespace)
URL      is the wmic_server URL (defaulting to wmic_server_url)
-d       DEBUG mode

EOT
exit 1
}
#-------------------------------------------------------------------------------

#=================================== MAIN ======================================

# ---------- GET Options
[ $# -ge 1 ] || usage

# Check for options
while getopts i:t:h:q:n:u:d OPT
do
   case $OPT in
   i) id="$OPTARG";;
   t) token="$OPTARG";;
   h) host="$OPTARG";;
   q) query="$OPTARG";;
   n) namespace="$OPTARG";;
   u) wmic_server_url="$OPTARG";;
   d) debug=1;;
   *) usage;;
   esac
done
shift `expr $OPTIND - 1`

if [ "$debug" ]; then
   set -x
fi

# run a curl using the POST method
curl -i -H "Content-Type: application/json" -X POST -d "{\"id\":\"$id\",\"token\":\"$token\",\"host\":\"$host\",\"query\":\"$query\",\"namespace\":\"$namespace\"}" $wmic_server_url


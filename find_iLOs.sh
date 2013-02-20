#!/bin/bash
#
# find_iLOs: Search a network for iLOs.
#

network=$1

ILOS_IPS=`mktemp /tmp/findilos.XXXXX`

# Get a list of IPs with the 17988 TCP port opened (iLO Virtual Media port)
# nmap options:
#    -n: Never do DNS resolution.
#    -sS: TCP SYN scans.
#    -PN: Treat all hosts as online (skip host discovery).
#    -p 17988: only scans port 17988.
#    -oG -: output scan in grepable format

./test/nmap -n -sS -PN -p 17988 -oG - $network | grep /open/ | awk '{print $2}' > $ILOS_IPS

ips=($(<$ILOS_IPS));

for i in "${ips[@]}"
do
    echo $i
done

# Delete temporary files
rm -f $ILOS_IPS

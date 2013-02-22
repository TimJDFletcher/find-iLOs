#!/bin/bash
#
# find_iLOs: Search a network for iLOs.
#

network=$1

ILOS_IPS=`mktemp /tmp/findilos.XXXXX`
ILO_XML=`mktemp /tmp/iloxml.XXXXX`

# FUNCTIONS

# Function that parses XML
# http://stackoverflow.com/questions/893585/how-to-parse-xml-in-bash
parse_xml(){
    local IFS=\>
    read -d \< ENTITY CONTENT
}

# MAIN

# Get a list of IPs with the 17988 TCP port opened (iLO Virtual Media port)
# nmap options:
#    -n: Never do DNS resolution.
#    -sS: TCP SYN scans.
#    -PN: Treat all hosts as online (skip host discovery).
#    -p 17988: only scans port 17988.
#    -oG -: output scan in grepable format

nmap -n -sS -PN -p 17988 -oG - $network | grep /open/ | awk '{print $2}' > $ILOS_IPS

ips=($(<$ILOS_IPS));

for ip in "${ips[@]}"
do
    # read the xmldata from iLO
    # -m: Maximum time in seconds that you allow the whole operation to take.
    # -f: (HTTP) Fail silently (no output at all) on server errors.
    # -s: silent mode.
    curl -m 3 -f -s http://$iloip/xmldata?item=All > $ILO_XML
    # XML format example
    # <?xml version="1.0"?>
    # <RIMP>
    #       <SBSN>CZC7515KS6 </SBSN> 
    #       <SPN>ProLiant DL380 G5</SPN>
    #       [...]
    #       <PN>Integrated Lights-Out 2 (iLO 2)</PN>
    #       <FWRI>2.05</FWRI>
    #       <HWRI>ASIC: 7</HWRI>
    #       <SN>ILOCZC7515KS6 </SN>
    # </RIMP>
    while parse_xml; do
        if [[ $ENTITY = "SBSN" ]]; then
            sbsn=$CONTENT
        elif [[ $ENTITY = "SPN" ]]; then
            spn=$CONTENT
        elif [[ $ENTITY = "PN" ]]; then
            pn=$CONTENT
        elif [[ $ENTITY = "FWRI" ]]; then
            fwri=$CONTENT
        elif [[ $ENTITY = "HWRI" ]]; then
            hwri=$CONTENT
        elif [[ $ENTITY = "SN" ]]; then
            sn=$CONTENT
        fi
    done < $ILO_XML
    echo "$ip | $sbsn | $spn | $pn | $fwri | $hwri | $sn"
    
done

# Delete temporary files
rm -f $ILOS_IPS $ILO_XML

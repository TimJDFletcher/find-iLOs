#!/bin/bash
#
# find_iLOs: Search a network for iLOs.
#

network=$1

ILOS_IPS=`mktemp /tmp/findilos.XXXXX`
ILO_XML=`mktemp /tmp/iloxml.XXXXX`

# FUNCTIONS
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
    # XML format
    # <?xml version="1.0"?><RIMP><HSI>
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
        fi
    done < $ILO_XML
    printf "%s %s\n" $ip $sbsn
    
done

# Delete temporary files
rm -f $ILOS_IPS $ILO_XML

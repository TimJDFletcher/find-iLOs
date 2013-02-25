#!/bin/bash
#
# find_iLOs: Search a network for iLOs.
#

# Check arguments
if [[ $# != 1 ]]; then
    echo "Usage: $0 network"
    echo " Example: $0 192.168.1.0/24"
    exit 1
fi

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

# Array of iLOs IPs
ips=($(<$ILOS_IPS));

# Print header
echo ""
echo "  IP Address   | iLO Type | iLO FW |   Server Model    | Server S/N "
echo "---------------|----------|--------|-------------------|------------"

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
    #       <FWRI>2.05</FWRI>
    #       <HWRI>ASIC: 7</HWRI>
    #       <SN>ILOCZC7515KS6 </SN>
    # </RIMP>
    while parse_xml; do
        if [[ $ENTITY = "SBSN" ]]; then
            sbsn=$CONTENT
        elif [[ $ENTITY = "SPN" ]]; then
            spn=$CONTENT
        elif [[ $ENTITY = "FWRI" ]]; then
            fwri=$CONTENT
        elif [[ $ENTITY = "HWRI" ]]; then
            hwri=$CONTENT
        elif [[ $ENTITY = "SN" ]]; then
            sn=$CONTENT
        fi
    done < $ILO_XML

    # iLO type:
    #   HWRI: 
    #     - TO       -> i-iLO
    #     - ASIC:  2 -> iLO-1
    #     - ASIC:  7 -> iLO-2
    #     - ASIC:  8 -> iLO-3
    case $hwri in
        "TO")
            ilotype="i-iLO"
            ;;
        "ASIC:  2")
            ilotype="iLO-1"
            ;;
        "ASIC:  7")
            ilotype="iLO-2"
            ;;
        "ASIC:  8")
            ilotype="iLO-3"
            ;;
        *)
            ilotype="N/A"
            ;;
    esac
        
    # Print iLO data
    printf "%-15s| %-8s | %-6s | %-18s| %-10s\n" "$ip" "$ilotype" "$fwri" "$spn" "$sbsn"
    
done

# Total number of iLOs found
num_ilos=${#ips[@]}
echo "$num_ilos iLOs found on $network"

# Delete temporary files
rm -f $ILOS_IPS $ILO_XML

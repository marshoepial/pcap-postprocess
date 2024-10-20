#!/usr/bin/env bash
set -e

pcap_file="$1"
base_name="${pcap_file%.*}"

dlt_config="uat:user_dlts:\"User 5 (DLT=152)\",\"ngap\",\"0\",\"\",\"0\",\"\""

# check number of arguments
if [ $# -ge 2 ] 
then
# 2 or more arguments - merge them with mergecap
merged_file="${base_name}_merged.pcapng"
mergecap -w "$merged_file" $@

# then run tshark on the merged file
pdml_file="${base_name}_merged.pdml"
tshark -r "$merged_file" -T pdml \
    -o "uat:user_dlts:\"User 5 (DLT=152)\",\"ngap\",\"0\",\"\",\"0\",\"\"" \
    -o "uat:user_dlts:\"User 7 (DLT=154)\",\"f1ap\",\"0\",\"\",\"0\",\"\"" \
    -o "uat:user_dlts:\"User 2 (DLT=149)\",\"udp\",\"0\",\"\",\"0\",\"\"" \
    > "$pdml_file"

else

#only one argument, so just run tshark
pdml_file="${base_name}.pdml"

tshark -r "$pcap_file" -T pdml \
    -o "uat:user_dlts:\"User 5 (DLT=152)\",\"ngap\",\"0\",\"\",\"0\",\"\"" \
    -o "uat:user_dlts:\"User 7 (DLT=154)\",\"f1ap\",\"0\",\"\",\"0\",\"\"" \
    -o "uat:user_dlts:\"User 2 (DLT=149)\",\"udp\",\"0\",\"\",\"0\",\"\"" \
    > "$pdml_file"

fi

# then run the python parser on the pdml file
python3 parse_pdml.py "$pdml_file"
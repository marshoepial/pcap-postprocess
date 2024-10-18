#!/usr/bin/bash

pcap_file="$1"
base_name="${pcap_file%.*}"

# check number of arguments
if [ $# -ge 2 ] 
then
# 2 or more arguments - merge them with mergecap
merged_file="${base_name}_merged.pcapng"
mergecap -w "$merged_file" $@

# then run tshark on the merged file
pdml_file="${base_name}_merged.pdml"
tshark -r "$merged_file" -T pdml > "$pdml_file"

else

#only one argument, so just run tshark
pdml_file="${base_name}.pdml"

tshark -r "$pcap_file" -T pdml > "$pdml_file"

fi
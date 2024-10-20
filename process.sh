#!/usr/bin/env bash
set -e

# check number of arguments
if [ $# -ge 2 ] 
then

# check if the first argument is "--live" for live capture
if [ "$1" == "--live" ]
then

# using live tshark capture, second arugment is interface, third is outfile
pdml_file="$3"
tshark -i "$2" -T pdml \
    -o "uat:user_dlts:\"User 5 (DLT=152)\",\"ngap\",\"0\",\"\",\"0\",\"\"" \
    -o "uat:user_dlts:\"User 7 (DLT=154)\",\"f1ap\",\"0\",\"\",\"0\",\"\"" \
    -o "uat:user_dlts:\"User 2 (DLT=149)\",\"udp\",\"0\",\"\",\"0\",\"\"" \
    -o "nas-5gs.null_decipher:TRUE" \
    -o "mac-nr.attempt_rrc_decode:TRUE" \
    -o "mac-nr.attempt_to_dissect_srb_sdus:TRUE" \
    -o "mac-nr.lcid_to_drb_mapping_source:From configuration protocol" \
    --enable-heuristic "mac_nr_udp" \
    > "$pdml_file"

else

pcap_file="$1"
base_name="${pcap_file%.*}"

# 2 or more arguments - merge them with mergecap
merged_file="${base_name}_merged.pcapng"
mergecap -w "$merged_file" $@

# then run tshark on the merged file
pdml_file="${base_name}_merged.pdml"
tshark -r "$merged_file" -T pdml \
    -o "uat:user_dlts:\"User 5 (DLT=152)\",\"ngap\",\"0\",\"\",\"0\",\"\"" \
    -o "uat:user_dlts:\"User 7 (DLT=154)\",\"f1ap\",\"0\",\"\",\"0\",\"\"" \
    -o "uat:user_dlts:\"User 2 (DLT=149)\",\"udp\",\"0\",\"\",\"0\",\"\"" \
    -o "nas-5gs.null_decipher:TRUE" \
    -o "mac-nr.attempt_rrc_decode:TRUE" \
    -o "mac-nr.attempt_to_dissect_srb_sdus:TRUE" \
    -o "mac-nr.lcid_to_drb_mapping_source:From configuration protocol" \
    --enable-heuristic "mac_nr_udp" \
    > "$pdml_file"

fi

else

pcap_file="$1"
base_name="${pcap_file%.*}"

#only one argument, so just run tshark
pdml_file="${base_name}.pdml"

tshark -r "$pcap_file" -T pdml \
    -o "uat:user_dlts:\"User 5 (DLT=152)\",\"ngap\",\"0\",\"\",\"0\",\"\"" \
    -o "uat:user_dlts:\"User 7 (DLT=154)\",\"f1ap\",\"0\",\"\",\"0\",\"\"" \
    -o "uat:user_dlts:\"User 2 (DLT=149)\",\"udp\",\"0\",\"\",\"0\",\"\"" \
    -o "nas-5gs.null_decipher:TRUE" \
    -o "mac-nr.attempt_rrc_decode:TRUE" \
    -o "mac-nr.attempt_to_dissect_srb_sdus:TRUE" \
    -o "mac-nr.lcid_to_drb_mapping_source:From configuration protocol" \
    --enable-heuristic "mac_nr_udp" \
    > "$pdml_file"

fi

# then run the python parser on the pdml file
python3 parse_pdml.py "$pdml_file"
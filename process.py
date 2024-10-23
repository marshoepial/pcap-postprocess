from io import StringIO
import json
import os
import re
import pyshark
import subprocess
import sys

# process.py
# USAGE: process.py -o <output file> [input file(s)...]
# -o: output file


args = sys.argv

if args[1] != "-o":
    print("Error: Output file must be defined with -o argument")
    sys.exit("1")

outputFile = args[2]
outFileRoot, ext = os.path.splitext(outputFile)

captureFile = ""

if len(args) > 4:
    # More than one file is specified, we should call mergeshark
    captureFile = f"{outFileRoot}_merged.pcapng"

    # run mergecap with all of the specified input files
    mergecapResult = subprocess.run(["mergecap", "-w", captureFile] + args[3:])

    if (mergecapResult.returncode != 0):
        print(mergecapResult.stderr)
        print("Mergecap error, exiting")
        sys.exit(1)
else:
    captureFile = args[3]


cap = pyshark.FileCapture(captureFile, custom_parameters=[
    "-o", 'uat:user_dlts:"User 5 (DLT=152)","ngap","0","","0",""',
    "-o", 'uat:user_dlts:"User 7 (DLT=154)","f1ap","0","","0",""',
    "-o", 'uat:user_dlts:"User 2 (DLT=149)","udp","0","","0",""',
    "-o", "nas-5gs.null_decipher:TRUE",
    "-o", "mac-nr.attempt_rrc_decode:TRUE",
    "-o", "mac-nr.attempt_to_dissect_srb_sdus:TRUE",
    "-o", "mac-nr.lcid_to_drb_mapping_source:From configuration protocol",
    "--enable-heuristic", "mac_nr_udp"
])

jsonArray = []
escapeChars = ['\n', '\t']

def removeEscapes(field):
    newField = field
    for escape in escapeChars:
        newField = newField.replace(escape, '')

    return newField

for packet in cap:
        packetLayers = {}

        for layer in packet.layers:

            layerFields = layer._get_all_field_lines()
            layerFields = list(map(removeEscapes, layerFields))
                 
            # print(layerFields)

            packetLayers[layer.layer_name] = layerFields

        jsonArray.append(packetLayers)

with open(outputFile, "w") as json_output:
    json.dump(jsonArray, json_output, indent=4)
import json
import os
import sys

from xml.sax import parse
from xml.sax.handler import ContentHandler
from xml.sax.xmlreader import AttributesImpl

CAPTURE_PROTO_NAMES = ["f1ap", "mac-nr", "ngap"]

class PDMLHandler(ContentHandler):

    def __init__(self):
        super().__init__()

        self.packets = []

    def startElement(self, name, attrs):
        #print(f"BEGIN: <{name}>, {attrs.keys()}")

        match name:
            # New packet is starting
            case "packet":
                self.currentPacket = {}

            # New protocol field - get the name of the protocol
            case "proto":
                self.currentProtoName = attrs.get("name")

                if self.currentProtoName in CAPTURE_PROTO_NAMES:
                    # Interested in the type of the packet here.
                    # We are just getting the wireshark "pretty-print" for now
                    self.currentPacket["showname"] = attrs.get("showname")

            # Generic pdml field. We need to handle this based on the current protocol context
            # TODO: extend to get source/dest for packets which support it?
            case "field":
                match self.currentProtoName:
                    case "geninfo":
                        self.handleGenInfoField(attrs)
                    case "mac-nr":
                        self.handleMacNrField(attrs)

    def handleGenInfoField(self, attrs: AttributesImpl):
        match attrs.get("name"):
            case "num":
                # Packet number
                self.currentPacket["num"] = attrs.get("value")
            case "timestamp":
                # Packet timestamp
                self.currentPacket["timestamp"] = attrs.get("value")

    def handleMacNrField(self, attrs: AttributesImpl):
        match attrs.get("name"):
            case "mac-nr.direction":
                # Xmit direction. 0 = UL, 1 = DL
                self.currentPacket["downlink"] = attrs.get("show")

    def endElement(self, name):
        #print(f"END: </{name}>")

        # if our current packet is ending, append it to the packet list.
        if name == "packet":
            self.packets.append(self.currentPacket)




pdmlFile = sys.argv[1]
print(f"Parsing document {pdmlFile}")

pdmlHandler = PDMLHandler()
parse(pdmlFile, pdmlHandler)

root, ext = os.path.splitext(pdmlFile)

with open(f"{root}.json", "w") as json_output:
    jsonContent = json.dump(pdmlHandler.packets, json_output, indent=4)
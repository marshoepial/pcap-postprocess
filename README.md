Capture/PCAP reading of packets and parsing to get information relevant to 5G/NR processes and handshakes.
The resulting JSON file can be compared with a "known good" handshake, based on 3GPP spec, to verify proper operation of a RAN.

### Run process.py to process a packet capture.
 - Add one or more .pcap capture files as arguments to read from earlier captures
     - e.g. `python3 process.py f1ap.pcap mac.pcap`

Capture/PCAP reading of packets and parsing to get information relevant to 5G/NR processes and handshakes.
The resulting JSON file can be compared with a "known good" handshake, based on 3GPP spec, to verify proper operation of a RAN.

### Run process.sh to process a packet capture.
 - Add one or more .pcap capture files as arguments to read from earlier captures
     - e.g. `./process.sh f1ap.pcap mac.pcap`
 - Use the `--live <interface> <.pdml output file>` option to capture packets live, then parse the result.
     - e.g. `./process.sh --live eth0 eth_capture.pdml`
     - Tshark will run indefinitely with this option - when done capturing packets, use ^C to finish the capture.

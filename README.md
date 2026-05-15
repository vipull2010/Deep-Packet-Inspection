# Deep-Packet-Inspection


DPI Engine - Java Port
A complete Java port of  Deep Packet Inspection engine.
Reads `.pcap` files, classifies traffic by application via TLS SNI extraction,
and can block/filter specific apps, IPs, or domains.
Requirements
Java 11 or higher (tested on Java 21)
Build
```bash
mkdir -p out
javac -d out src/dpi/*.java
```
Run
```bash
# Basic — process and forward all packets
java -cp out dpi.DpiEngine test_dpi.pcap output.pcap

# With blocking rules
java -cp out dpi.DpiEngine test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok

# Block by IP
java -cp out dpi.DpiEngine test_dpi.pcap output.pcap --block-ip 192.168.1.50

# Block by domain substring
java -cp out dpi.DpiEngine test_dpi.pcap output.pcap --block-domain facebook
```
Project Structure
```
DPI_Engine_Java/
├── src/
│   └── dpi/
│       ├── DpiEngine.java      # Main entry point (port of main_working.cpp)
│       ├── PcapReader.java     # Reads .pcap files (port of pcap_reader.cpp)
│       ├── PcapWriter.java     # Writes .pcap files
│       ├── PacketParser.java   # Parses Ethernet/IP/TCP/UDP headers (port of packet_parser.cpp)
│       ├── SniExtractor.java   # TLS SNI + HTTP Host extraction (port of sni_extractor.cpp)
│       ├── AppType.java        # Application classification enum (port of types.h/types.cpp)
│       ├── FiveTuple.java      # Connection identifier struct (port of types.h)
│       ├── Flow.java           # Per-flow state tracking
│       ├── RawPacket.java      # Raw packet holder (port of RawPacket struct)
│       ├── ParsedPacket.java   # Parsed packet fields (port of ParsedPacket struct)
│       └── BlockingRules.java  # Blocking rules engine
├── test_dpi.pcap               # Sample capture for testing
└── README.md
```
What It Does
Reads every packet from the input `.pcap` file
Parses Ethernet → IPv4 → TCP/UDP headers
For HTTPS (port 443): extracts the SNI hostname from the TLS Client Hello
For HTTP (port 80): extracts the Host header
Maps the hostname to an application (YouTube, TikTok, Facebook, etc.)
Checks blocking rules; if matched, drops the packet
Writes non-blocked packets to the output `.pcap`
Prints a full report with per-app packet counts
Blocking Rules
Option	Example	What it blocks
`--block-app`	`--block-app YouTube`	All packets classified as YouTube
`--block-ip`	`--block-ip 192.168.1.50`	All packets from that source IP
`--block-domain`	`--block-domain facebook`	Any flow whose SNI contains "facebook"
Supported Applications
Google, YouTube, Facebook, Instagram, WhatsApp, Twitter/X, Netflix,
Amazon, Microsoft, Apple, Telegram, TikTok, Spotify, Zoom, Discord,
GitHub, Cloudflare, and more.

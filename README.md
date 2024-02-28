# pcap Fingerprint Analysis Tool

This Python script provides a command-line interface for analyzing pcap (Packet Capture) files to extract network traffic fingerprints. It leverages various tools such as `tshark`, `p0f`, and `Snort` for deep packet inspection and analysis.

## Features

- **Protocol Analysis**: Utilizes `tshark` to perform protocol analysis, extracting information such as source IP, destination IP, TCP/UDP ports, and protocols.
- **p0f Integration**: Incorporates `p0f` to identify OS and application signatures associated with IP addresses.
- **Snort Analysis**: Utilizes `Snort` intrusion detection system to analyze network traffic and extract application layer information.
- **Output to CSV**: Saves the extracted fingerprint information into a CSV file for further analysis and processing.

## Prerequisites

- Python 3.x
- `tshark`: Packet analyzer tool (part of Wireshark)
- `p0f`: Passive OS fingerprinting tool
- `Snort`: Intrusion detection and prevention system

## Installation

1. Clone or download the repository to your local machine.
2. Ensure all dependencies (`tshark`, `p0f`, `Snort`) are installed and configured properly.

## Usage

Run the script with appropriate command-line options to analyze pcap files:

```bash
python3 fingerprint.py -f <PATH_TO_PCAP> -s <SNORT_PATH> -c <SNORT_CONFIG.LUA>
```

Example usage:

```bash
python3 fingerprint.py -f ../../some.pcap -s /opt/snort3/ -c snort.lua
```

For analyzing multiple pcap files listed in a file:

```bash
python3 fingerprint.py -s /opt/snort3 -c snort.lua -l pcapfiles.list --verbose
```

## Command-line Options

- `-f, --file`: Path to the pcap file for analysis.
- `-s, --snort`: Path to the Snort base directory.
- `-c, --config`: Path to the Snort configuration Lua file.
- `-l, --list`: Path to a file containing a list of pcap files to process.
- `-o, --out`: Path to the output directory for saving fingerprint information (default: current directory).
- `--verbose`: Enable verbose output.
- `--noP0f`: Skip p0f analysis.
- `--noSnort`: Skip Snort analysis.

## Output

The script generates a CSV file containing the extracted fingerprint information for each pcap file analyzed.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

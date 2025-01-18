# Network Sniffer

A Python-based network packet sniffer that captures and analyzes network traffic in real-time. This tool uses the Scapy library to capture packets and provide detailed information about network communications, including packet payload analysis and protocol-specific details.

## Features

- Real-time packet capture and analysis
- Detailed protocol analysis
  - TCP analysis (flags, sequence numbers, window size)
  - UDP analysis
  - ICMP type and code identification
  - HTTP request/response analysis
  - DNS query/response analysis
- Payload Analysis
  - Hex dump with ASCII representation
  - Text content detection and decoding
  - Protocol-specific payload parsing
- Network statistics tracking
  - Packet sizes and averages
  - Total bytes captured
  - Protocol distribution
  - Top IP conversations
  - Most active ports
- Comprehensive Logging
  - Automatic file creation with timestamps
  - Save all captured data to file
  - Detailed packet information
  - Traffic analysis
  - Statistics and summaries
  - Timestamps for all events
- Source and destination IP/port tracking
- Flexible packet filtering
- Command-line interface with customizable options

## Requirements

- Python 3.x
- Scapy library
- Administrator/root privileges (required for packet capture)

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

<!-- Run the script with administrator/root privileges:

```bash
# Basic usage (capture all packets)
python network_sniffer.py

# Capture packets on specific interface
python network_sniffer.py -i eth0

# Apply filter (e.g., capture only TCP traffic)
python network_sniffer.py -f "tcp"

# Capture specific number of packets
python network_sniffer.py -c 100

# Save capture to specific file
python network_sniffer.py -o capture.log

# Combine options
python network_sniffer.py -i eth0 -f "port 80" -o http_capture.log
```

### Command Line Options

- `-i, --interface`: Specify network interface to capture packets
- `-f, --filter`: BPF filter string to filter packets
- `-c, --count`: Number of packets to capture (0 for infinite)
- `-o, --output`: Output file to save capture log (optional, auto-generates if not specified)

## Example Filters

- TCP traffic only: `"tcp"`
- UDP traffic only: `"udp"`
- Traffic on port 80: `"port 80"`
- Traffic to/from specific IP: `"host 192.168.1.1"`
- Combine filters: `"tcp and port 443"`

## Output Information

The sniffer provides comprehensive information about each packet:

### Basic Information
- Timestamp
- Source and destination IP addresses
- Source and destination ports
- Protocol information
- Packet size

### Protocol-Specific Details
- TCP: Flags, sequence numbers, acknowledgment numbers, window size
- UDP: Payload length
- ICMP: Type and code
- HTTP: Method, path, status code, headers
- DNS: Queries and responses

### Payload Analysis
- Hex dump with ASCII representation
- Decoded text content (when applicable)
- Protocol-specific payload parsing

### Statistics (shown at end of capture)
- Total packets and bytes captured
- Average packet size
- Protocol distribution
- Top IP conversations
- Most active ports

### Log File Format
The log file includes:
- Capture start and end times
- Complete packet details
- Protocol-specific information
- Payload data in both hex and text format
- Final statistics and summary
- Any errors or warnings during capture

### Automatic File Creation
If no output file is specified:
- Creates a timestamped file (e.g., capture_20250118_090806.log)
- Creates output directory if it doesn't exist
- Automatically handles file creation and error handling

## GUI Version -->

The Network Sniffer now includes a Wireshark-like GUI interface for easier packet analysis. To run the GUI version:

```bash
python network_sniffer_gui.py
```

### GUI Features and Usage

#### Start Capturing
- Select your network interface from the dropdown menu at the top
- Click "▶ Start Capture" to begin capturing packets
- Click "⏹ Stop Capture" when you want to stop the capture

#### Analyzing Packets
- The top pane shows the list of captured packets
- Click on any packet to view its details
- The middle pane shows the packet's protocol layers in a tree view
- The bottom pane displays a hex dump of the packet with ASCII representation

#### Filtering
- Use the filter box in the toolbar to search through captured packets
- Type any text and click "Apply" to filter the packet list
- The filter searches across all packet fields (source, destination, protocol, etc.)

#### Statistics
- Click the "📊 Statistics" button to open the statistics window
- View real-time statistics including:
  - Total number of packets captured
  - Protocol distribution
  - Traffic patterns
  - Most active protocols

### Screenshots

[Coming Soon]

## Note

This tool requires administrator/root privileges to capture packets. Run with appropriate permissions.

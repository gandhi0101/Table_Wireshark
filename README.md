## PCAPNG Packet Table Extractor

This Python script extracts packet details from a `.pcapng` file and generates a table displaying information such as MAC addresses, IP addresses, ports, protocol, application, TCP flags, and the network gateway, if found.

## Requirements

Before using this script, ensure that you have the following Python packages installed:

- **Scapy**: Used to analyze network packets.
- **Tabulate**: Used to display the packet data in a table format.
- **Colorama**: Used to highlight the gateway in the output.

You can install these dependencies with the following command:

```bash
pip install scapy tabulate colorama
```

## Usage

1. Place your `.pcapng` file in the same directory as the script or provide the absolute path to it.
   
2. Run the script from the command line with the `.pcapng` file as an argument:

   ```bash
   python table_wireshark.py yourfile.pcapng
   ```

   Replace `yourfile.pcapng` with the actual filename of your capture file.

3. The script will analyze the packets in the `.pcapng` file and display a table with the following columns:

   - **MAC Origen**: Source MAC address
   - **MAC Destino**: Destination MAC address
   - **IP Origen**: Source IP address (highlighted in green if it's the gateway)
   - **IP Destino**: Destination IP address (highlighted in green if it's the gateway)
   - **Puerto Origen**: Source port (for TCP/UDP packets)
   - **Puerto Destino**: Destination port (for TCP/UDP packets)
   - **Protocolo**: Protocol used (TCP, UDP, etc.)
   - **Aplicación**: Application inferred from common ports (e.g., HTTP, HTTPS)
   - **Flags**: TCP flags (for TCP packets)
   - **Tipo**: Ethernet type (IPv4, IPv6, etc.)

   Additionally, if a gateway is detected via ARP packets, the script will print and highlight the detected gateway IP address.

## Example

```bash
python table_wireshark.py capture.pcapng
```

This command will generate a table with the network traffic details from the `capture.pcapng` file, and the detected gateway IP (if found) will be highlighted in green.

## Notes

- The application column will attempt to infer the service based on standard ports (e.g., 80 for HTTP, 443 for HTTPS).
- If no recognized application is detected, the script will mark it as "Unknown."
- Ensure that the `.pcapng` file is valid and contains network traffic data for accurate analysis.
- The script now detects and highlights the gateway based on ARP responses.


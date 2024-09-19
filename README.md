# PCAPNG Packet Table Extractor

This Python script extracts packet details from a `.pcapng` file and generates a table displaying information such as MAC addresses, IP addresses, ports, protocol, application, and TCP flags.

## Requirements

Before using this script, ensure that you have the following Python packages installed:

- **Scapy**: Used to analyze network packets.
- **Tabulate**: Used to display the packet data in a table format.

You can install these dependencies with the following command:

```bash
pip install scapy tabulate colorama
```

## Usage

1. Place your `.pcapng` file in the same directory as the script or provide the absolute path to it.
   
2. Run the script from the command line with the `.pcapng` file as an argument:

   ```bash
   python script.py yourfile.pcapng
   ```

   Replace `yourfile.pcapng` with the actual filename of your capture file.

3. The script will analyze the packets in the `.pcapng` file and display a table with the following columns:

   - **MAC Origen**: Source MAC address
   - **MAC Destino**: Destination MAC address
   - **IP Origen**: Source IP address
   - **IP Destino**: Destination IP address
   - **Puerto Origen**: Source port (for TCP/UDP packets)
   - **Puerto Destino**: Destination port (for TCP/UDP packets)
   - **Protocolo**: Protocol used (TCP, UDP, etc.)
   - **Aplicación**: Application inferred from common ports (e.g., HTTP, HTTPS)
   - **Flags**: TCP flags (for TCP packets)
   - **Tipo**: Ethernet type (IPv4, IPv6, etc.)

## Example

```bash
python script.py capture.pcapng
```

This command will generate a table with the network traffic details from the `capture.pcapng` file.

## Notes

- The application column will attempt to infer the service based on standard ports (e.g., 80 for HTTP, 443 for HTTPS).
- If no recognized application is detected, the script will mark it as "Unknown."
- Ensure that the `.pcapng` file is valid and contains network traffic data for accurate analysis.

---

Feel free to customize it further if you have specific needs!

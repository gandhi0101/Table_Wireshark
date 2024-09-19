import sys
import scapy.all as scapy
from tabulate import tabulate

# Verificar si se han pasado los argumentos correctamente
if len(sys.argv) != 2:
    print("Debes proporcionar exactamente un archivo pcapng como parámetro.")
    sys.exit(1)

# Obtener el archivo pcapng desde los argumentos
pcapng_file = sys.argv[1]

# Leer el archivo pcapng
packets = scapy.rdpcap(pcapng_file)

# Crear lista para almacenar la información extraída
packet_data = []

# Definir algunas aplicaciones basadas en los puertos comunes
app_protocols = {
    80: "HTTP",
    443: "HTTPS",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    53: "DNS",
    67: "DHCP",
    21: "FTP"
}

# Iterar sobre cada paquete en el archivo
for packet in packets:
    # Verificar si el paquete tiene capa Ethernet (MAC)
    if packet.haslayer(scapy.Ether):
        src_mac = packet[scapy.Ether].src
        dst_mac = packet[scapy.Ether].dst
        eth_type = packet[scapy.Ether].type
    else:
        src_mac = dst_mac = eth_type = None
    
    # Verificar si tiene capa IP
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        proto = packet[scapy.IP].proto
    else:
        src_ip = dst_ip = proto = None

    # Asignar valores iniciales
    src_port = dst_port = protocol = flags = app = None
    
    # Verificar si el paquete tiene capa TCP/UDP
    if packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
        protocol = "TCP"
        flags = packet[scapy.TCP].flags
        app = app_protocols.get(src_port) or app_protocols.get(dst_port) or "Desconocido"
    elif packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
        protocol = "UDP"
        app = app_protocols.get(src_port) or app_protocols.get(dst_port) or "Desconocido"

    # Añadir los datos a la lista
    packet_data.append([src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, app, flags, eth_type])

# Generar tabla
headers = [
    "MAC Origen", "MAC Destino", "IP Origen", "IP Destino", 
    "Puerto Origen", "Puerto Destino", "Protocolo", "Aplicación", "Flags", "Tipo"
]
table = tabulate(packet_data, headers, tablefmt="grid")

# Mostrar tabla
print(table)

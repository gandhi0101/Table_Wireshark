import sys
import scapy.all as scapy
from tabulate import tabulate
from colorama import Fore, Style
import csv

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
gateway_ip = None  # Para almacenar el IP del gateway si se detecta

# Diccionario para asociar los puertos con protocolos conocidos
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

# Función para interpretar flags TCP
def interpret_flags(flags):
    flag_str = []
    if flags & 0x02:  # SYN
        flag_str.append("SYN")
    if flags & 0x10:  # ACK
        flag_str.append("ACK")
    if flags & 0x01:  # FIN
        flag_str.append("FIN")
    if flags & 0x04:  # RST
        flag_str.append("RST")
    if flags & 0x08:  # PSH
        flag_str.append("PSH")
    if flags & 0x20:  # URG
        flag_str.append("URG")
    return " ".join(flag_str) if flag_str else "None"

# Buscar el gateway en paquetes ARP
for packet in packets:
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:  # Respuesta ARP
        gateway_ip = packet[scapy.ARP].psrc  # IP de origen de la respuesta ARP (posible gateway)
        break

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
        flags = interpret_flags(packet[scapy.TCP].flags)
        app = app_protocols.get(src_port) or app_protocols.get(dst_port) or "Unknown"
    elif packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
        protocol = "UDP"
        app = app_protocols.get(src_port) or app_protocols.get(dst_port) or "Unknown"

    # Si se encuentra el gateway en el IP de destino o de origen, resáltalo
    if src_ip == gateway_ip or dst_ip == gateway_ip:
        src_ip = Fore.GREEN + src_ip + Style.RESET_ALL if src_ip == gateway_ip else src_ip
        dst_ip = Fore.GREEN + dst_ip + Style.RESET_ALL if dst_ip == gateway_ip else dst_ip

    # Añadir los datos a la lista
    packet_data.append([src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, app, flags, eth_type])

# Generar tabla
headers = [
    "MAC Origen", "MAC Destino", "IP Origen", "IP Destino", 
    "Puerto Origen", "Puerto Destino", "Protocolo", "Aplicación", "Flags", "Tipo"
]
table = tabulate(packet_data, headers, tablefmt="plain")

# Mostrar el gateway detectado
if gateway_ip:
    print(f"{Fore.GREEN}Detected Gateway IP: {gateway_ip}{Style.RESET_ALL}")
else:
    print("No Gateway detected.")

# Mostrar tabla
print(table)

# Guardar los resultados en un archivo CSV
csv_file = "packet_data.csv"
with open(csv_file, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(headers)  # Escribir los encabezados
    for row in packet_data:
        # Remover los colores para el CSV
        clean_row = [str(col).replace(Fore.GREEN, "").replace(Style.RESET_ALL, "") for col in row]
        writer.writerow(clean_row)
print(f"CSV file '{csv_file}' has been saved successfully.")

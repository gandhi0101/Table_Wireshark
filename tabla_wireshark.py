import sys
import scapy.all as scapy
from tabulate import tabulate
import pandas as pd  # Importar pandas para la creación del archivo Excel

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
        flags = interpret_flags(packet[scapy.TCP].flags)  # Interpretar flags TCP
        app = app_protocols.get(src_port) or app_protocols.get(dst_port) or "Desconocido"
    elif packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
        protocol = "UDP"
        app = app_protocols.get(src_port) or app_protocols.get(dst_port) or "Desconocido"

    # Añadir los datos a la lista
    packet_data.append([src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, app, flags, eth_type])

# Definir encabezados
headers = [
    "MAC Origen", "MAC Destino", "IP Origen", "IP Destino", 
    "Puerto Origen", "Puerto Destino", "Protocolo", "Aplicación", "Flags", "Tipo"
]

# Generar tabla y mostrarla
table = tabulate(packet_data, headers, tablefmt="grid")
print(table)

# Crear un DataFrame de pandas con los datos
df = pd.DataFrame(packet_data, columns=headers)

# Guardar la tabla en un archivo Excel
output_excel_file = "packet_data.xlsx"
df.to_excel(output_excel_file, index=False)

print(f"La tabla se ha guardado correctamente en el archivo {output_excel_file}")

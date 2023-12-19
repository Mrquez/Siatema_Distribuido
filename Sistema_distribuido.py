import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
import matplotlib.pyplot as plt

# Estructura de datos para almacenar detalles de paquetes
columns = ['Timestamp', 'Type', 'Source IP', 'Destination IP', 'Size']
packet_data = pd.DataFrame(columns=columns)

def packet_callback(packet):
    if IP in packet:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        packet_type = None

        if TCP in packet:
            packet_type = 'TCP'
        elif UDP in packet:
            packet_type = 'UDP'
        elif ICMP in packet:
            packet_type = 'ICMP'

        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        packet_size = len(packet)

        # Almacena los detalles del paquete en el DataFrame
        global packet_data
        packet_data = packet_data.append(
            {'Timestamp': timestamp,
             'Type': packet_type,
             'Source IP': source_ip,
             'Destination IP': dest_ip,
             'Size': packet_size},
            ignore_index=True
        )

# Captura de paquetes durante 60 segundos
sniff(prn=packet_callback, store=0, timeout=60)

# Informe general
print("Detalles del tráfico capturado:")
print(packet_data)

# Generación de informes gráficos
plt.figure(figsize=(12, 6))

# Gráfico de cantidad de paquetes por tipo
plt.subplot(121)
packet_data['Type'].value_counts().plot(kind='bar', rot=0)
plt.title('Cantidad de Paquetes por Tipo')

# Gráfico de tráfico a lo largo del tiempo
plt.subplot(122)
packet_data['Timestamp'] = pd.to_datetime(packet_data['Timestamp'])
traffic_over_time = packet_data.resample('1T', on='Timestamp').size()
traffic_over_time.plot()
plt.title('Tráfico a lo largo del Tiempo')

plt.tight_layout()
plt.show()

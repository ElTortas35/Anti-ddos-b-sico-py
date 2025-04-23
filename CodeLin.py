from scapy.all import *
import os
# Diccionario para almacenar el conteo de SYN por IP de origen
conteo_syn = {}

def detectar_inundacion_syn(paquete):
    """Detecta un posible ataque de inundación SYN y bloquea la IP si es necesario."""
    if paquete.haslayer(TCP) and paquete[TCP].flags == 'S':
        ip_origen = paquete[IP].src
        
        # Incrementa el conteo de SYN para esta IP
        if ip_origen in conteo_syn:
            conteo_syn[ip_origen] += 1
        else:
            conteo_syn[ip_origen] = 1
        
        # Define un umbral para considerar un ataque (ajusta este valor según sea necesario)
        umbral = 50
        
        # Si el conteo supera el umbral, bloquea la IP
        if conteo_syn[ip_origen] > umbral:
            print(f"¡Posible ataque de inundación SYN detectado desde {ip_origen}!")
            print(f"¡Bloqueando IP: {ip_origen}")
            
            #El bloqueo de la IP usando iptables
           
            os.system(f"iptables -A INPUT -s {ip_origen} -j DROP")
            
            
            
            # Reinicia el conteo para esta IP
            conteo_syn[ip_origen] = 0

# Captura paquetes en la interfaz de red
sniff(filter="tcp", prn=detectar_inundacion_syn, iface="eht0", store=0)

#!/usr/bin/env python3
import os
import time
import random
import re
from scapy.all import *


TARGET = os.getenv('RTMP_SERVER', 'srs-server')
PORT   = int(os.getenv('RTMP_PORT', '1935'))
IFACE  = os.getenv('INTERFACE', 'eth0')
print("[DEBUG] Interfaces disponibles:", get_if_list())
print("[FUZZER] Arrancando en interfaz", IFACE, "hacia", TARGET, "puerto", PORT)
time.sleep(1) 

def fuzz_random():
    """Inyección 1: payload aleatorio puro"""
    sport = random.randint(1024, 65535)
    print(f"[FUZZER] Enviando payload aleatorio desde puerto {sport}")
    ip   = IP(dst=TARGET)
    syn  = ip/TCP(dport=PORT, sport=sport, flags='S')
    synack = sr1(syn, timeout=2, iface=IFACE, verbose=False)
    if not synack:
        print("[FUZZER] No hubo SYN-ACK, abortando fuzz_random")
        return
    ack = ip/TCP(dport=PORT, sport=sport, flags='A',
                 seq=syn.seq+1, ack=synack.seq+1)
    send(ack, iface=IFACE, verbose=False)

    payload = bytes(random.getrandbits(8) for _ in range(128))
    pkt = ip/TCP(dport=PORT, sport=sport, flags='PA',
                 seq=syn.seq+1, ack=synack.seq+1)/Raw(load=payload)
    send(pkt, iface=IFACE)

def fuzz_flv_header():
    """Inyección 2: cabecera FLV corrupta"""
    sport = random.randint(1024, 65535)
    print(f"[FUZZER] Inyectando FLV header corrupto desde puerto {sport}")
    ip   = IP(dst=TARGET)
    syn  = ip/TCP(dport=PORT, sport=sport, flags='S')
    synack = sr1(syn, timeout=2, iface=IFACE, verbose=False)
    if not synack:
        print("[FUZZER] No hubo SYN-ACK, abortando fuzz_flv_header")
        return
    ack = ip/TCP(dport=PORT, sport=sport, flags='A',
                 seq=syn.seq+1, ack=synack.seq+1)
    send(ack, iface=IFACE, verbose=False)

    malformed = b'FLV\x99\x99\x99' + b'\x00'*20
    pkt = ip/TCP(dport=PORT, sport=sport, flags='PA',
                 seq=syn.seq+1, ack=synack.seq+1)/Raw(load=malformed)
    send(pkt, iface=IFACE)

def get_valid_packet():
    print("[FUZZER] Sniffeando todos los PSH (TCP datos) en puerto 1935...")
    bpf = f"tcp port {PORT}"
    print("[DEBUG] Voy a dormir 1s y luego sniff...")
    time.sleep(1)
    print("[DEBUG] Iniciando sniff ahora")
    pkts = sniff(iface=IFACE, filter=bpf, timeout=30, count=0)
    print(f"[DEBUG] Capturados {len(pkts)} paquetes")
    keywords = [
        b'\x02\x00\x07connect',   # AMF0 connect
        b'\x02\x00\x0ccreateStream',  # AMF0 createStream
        b'publish',                # literal publish
        b'/live/stream',           # literal stream 
    ]

    for p in pkts:
        if Raw in p:
            data = p[Raw].load
            for k in keywords:
                if k in data:
                    print(f"[FUZZER] Paquete útil con keyword {k!r}: {p.summary()}")
                    return p

    for p in pkts:
        if Raw in p and len(p[Raw].load) > 0:
            print(f"[FUZZER] Fallback: usando paquete {p.summary()}")
            return p

    return None

def mod_field1(pkt):
    """Mod 1: variar el primer byte del payload"""
    print("[FUZZER] Modificando primer byte del payload")
    sport = pkt[TCP].sport
    seq   = pkt[TCP].seq
    print(f"[FUZZER][MOD1] sport={sport}, seq={seq} → incrementé primer byte")
    p = pkt.copy()
    data = bytearray(p[Raw].load)
    data[0] = (data[0] + 1) % 256
    p[Raw].load = bytes(data)
    del p[IP].chksum
    del p[TCP].chksum

    send(p, iface=IFACE)

def mod_field2(pkt):
    """Mod 2: alterar transactionId a 9999"""
    sport = pkt[TCP].sport
    sport = pkt[TCP].sport; seq = pkt[TCP].seq
    print(f"[FUZZER][MOD2] sport={sport}, seq={seq} → transactionId=9999")
    print("[FUZZER] Alterando transactionId")
    p = pkt.copy()
    load = p[Raw].load
    newload = re.sub(rb'"transactionId"\s*:\s*\d+', b'"transactionId":9999', load)
    p[Raw].load = newload
    del p[IP].chksum
    del p[TCP].chksum

    send(p, iface=IFACE)

def mod_field3(pkt):
    """Mod 3: cambiar nombre del stream"""
    sport = pkt[TCP].sport
    sport = pkt[TCP].sport; seq = pkt[TCP].seq
    print(f"[FUZZER][MOD3] sport={sport}, seq={seq} → stream→evilstr")
    print("[FUZZER] Cambiando nombre del stream")
    p = pkt.copy()
    p[Raw].load = p[Raw].load.replace(b'/live/stream', b'/live/evilstr')
    del p[IP].chksum
    del p[TCP].chksum

    send(p, iface=IFACE)

def mod_body_size(pkt):
   
    ip = IP(dst=TARGET)
    sport = random.randint(40000, 60000)

#  SYN
    syn = ip/TCP(sport=sport, dport=PORT, flags="S", seq=1000)
    synack = sr1(syn, iface=IFACE, timeout=2)

    if synack is None:
      print("No SYN-ACK, no conexión")
      return

#  ACK
    ack = ip/TCP(sport=sport, dport=PORT, flags="A", seq=1001, ack=synack.seq + 1)
    send(ack, iface=IFACE)

    print("[FUZZER] Modificando Body size (AMF length)")
    
    sport = pkt[TCP].sport; seq = pkt[TCP].seq
    print(f"[FUZZER][MOD3] sport={sport}, seq={seq} → stream→evilstr")
    p = pkt.copy()
    raw = bytearray(p[Raw].load)
    
    print("Original body size:", raw[3:6].hex())

    raw[3] = 0x00
    raw[4] = 0x00
    raw[5] = 0x10  #total body size = 0x000010 = 16

    p[Raw].load = bytes(raw)
    
    p[TCP].sport = sport
    p[TCP].seq = 1001
    p[TCP].seq = synack.seq + 1
    del p[IP].chksum
    del p[TCP].chksum
    p.show()
    print("Bytes:", bytes(p).hex())
    send(p, iface=IFACE, verbose=1)
    print("Modificado body size:", p[Raw].load[3:6].hex())
    print(f"[FUZZER][MOD3] sport={p[TCP].sport}")
    
    
if __name__ == "__main__":
    
    # captura de paquete
    valid = get_valid_packet()
    if not valid:
        print("[FUZZER] No se encontró paquete útil, saliendo.")
        exit(1)

    #tres modificaciones sobre el paquete valido
    
    mod_body_size(valid)
    time.sleep(2)
    mod_field1(valid)
    time.sleep(2)
    mod_field2(valid)
    time.sleep(2)
    
    print("[FUZZER] ¡Fuzzing e inyecciones/modificaciones completadas!")
    
       #dos inyecciones
    fuzz_random()
    time.sleep(5)
    fuzz_flv_header()
    time.sleep(5)


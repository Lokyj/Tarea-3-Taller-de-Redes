#!/bin/bash
# verify.sh - Versión mejorada

echo "=== Diagnóstico de Red ==="
echo "1. Interfaz eth0:"
ip addr show eth0

echo -e "\n2. Tabla de rutas:"
ip route show

echo -e "\n3. Resolviendo MAC del gateway (172.18.0.1):"
arping -c 2 172.18.0.1 || echo "Arping no disponible, usando ping"
ping -c 2 172.18.0.1 >/dev/null
arp -n 172.18.0.1 || echo "ARP no disponible"

echo -e "\n4. Verificando conectividad con srs-server:"
ping -c 2 srs-server >/dev/null && echo "OK" || echo "Fallo"

echo -e "\n=== Ejecutando Fuzzer ==="
python fuzzer.py --action fuzz_handshake --wait-handshake

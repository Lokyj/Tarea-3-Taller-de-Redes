# RTMP y fuzzing con Scapy

Este repositorio incluye una infraestructura de contenedores Docker para:

1. **Servidor SRS** (Simple Real-time Server) que expone un servicio RTMP.  
2. **Cliente simple** que publica un video en bucle hacia el servidor RTMP.  
3. **Contenedor Fuzzer** basado en Scapy para inyectar y modificar tráfico RTMP.  ## Prerrequisitos

Para el correcto funcionamiento de todo, se debe tener instalado en una máquina virtual (recomendado) lo siguiente:
- Docker-compose 
- Wireshark (opcional pero recomendado)

## Construcción y arranque de los servicios
Con docker-compose instalado, ejecuta en la raíz del proyecto:

```bash
sudo docker-compose up --build -d
```

Esto debería crear todas las imágenes necesarias y levantarlas en modo detach. Para verificar el estado ejecuta:

``` bash
sudo docker-compose ps
```

Deberías ver:
- srs-server en estado Up (puertos 1935 y 1985 expuestos)

- simple-client en estado Up (publicando video)

- rtmp-fuzzer en estado Up (si no, revisa logs)

## Visualización del stream

Desde tu PC principal (fuera de la VM), abre VLC y pon la URL:

``` bash
rtmp://<IP_DE_LA_VM>:1935/live/stream
```
## Inyección y modificación de paquetes con Scapy

El contenedor rtmp-fuzzer contiene un script principal fuzz_rtmp.py que ejecuta:

1. **2 inyecciones**:

- fuzz_random(): envía 128 bytes aleatorios tras handshake TCP.

- fuzz_flv_header(): envía un encabezado FLV corrupto.

2. **3 modificaciones** sobre un paquete RTMP válido capturado:

- mod_field1(): varía el primer byte del payload.

- mod_field2(): altera "transactionId" a 9999.

- mod_field3(): cambia /live/stream por /live/evilstr.

Este script se ejecutará automáticamente cuando se inicie el contenedor. Para verificar los cambios realizados abre Wireshark y realiza lo siguiente:

- Asegúrate de usar la interfaz adecuada
- Usa el siguiente filtro: 
``` bash
tcp.port == 1935
```

- Busca los cambios de payload segun se especifica en cada tecnica.

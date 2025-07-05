FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ffmpeg \
      wget \
      vlc \
      ca-certificates \
      tcpdump && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m vlcuser

RUN mkdir -p /home/vlcuser/video && \
    wget -O /home/vlcuser/video/sample.mp4 \
    https://test-videos.co.uk/vids/bigbuckbunny/mp4/h264/360/Big_Buck_Bunny_360_10s_1MB.mp4 && \
    chown -R vlcuser:vlcuser /home/vlcuser/video

COPY start-publish.sh /home/vlcuser/start-publish.sh
RUN chmod +x /home/vlcuser/start-publish.sh && \
    chown vlcuser:vlcuser /home/vlcuser/start-publish.sh


USER vlcuser
#cuando arranque el contenedor, se ejecutará start-publish.sh
ENTRYPOINT ["/home/vlcuser/start-publish.sh"]

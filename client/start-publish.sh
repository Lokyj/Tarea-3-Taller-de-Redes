#!/usr/bin/env bash
set -e

SRS_RTMP="rtmp://srs-server/live/stream"
VIDEO_FILE="/home/vlcuser/video/sample.mp4"

echo "[CLIENT] Esperando a que SRS se inicie..."
sleep 20

sleep 10

echo "[CLIENT] Iniciando publicación continua a $SRS_RTMP ..."
ffmpeg -re -stream_loop -1 -i "$VIDEO_FILE" \
       -c copy -f flv "$SRS_RTMP" > /dev/null 2>&1 &

sleep 10

echo "[CLIENT] Reproduciendo stream con VLC desde $SRS_RTMP ..."
cvlc --intf dummy --no-video --no-audio --no-xlib "$SRS_RTMP"


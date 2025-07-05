
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      git \
      wget \
      unzip \
      tcl \
      cmake \
      autoconf \
      automake \
      libtool \
      libssl-dev \
      libpcre3-dev \
      pkg-config \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/src
RUN git clone --depth=1 -b v5.0-r3 https://github.com/ossrs/srs

WORKDIR /usr/local/src/srs/trunk

RUN ./configure && \
    make -j$(nproc)


RUN mkdir -p /usr/local/srs/conf && \
    mkdir -p /usr/local/srs/objs && \
    mkdir -p /usr/local/srs/logs && \
    cp -r /usr/local/src/srs/trunk/conf/* /usr/local/srs/conf/ && \
    cp -r /usr/local/src/srs/trunk/objs /usr/local/srs/ && \
    chmod -R 755 /usr/local/srs

EXPOSE 1935 1985

WORKDIR /usr/local/srs

COPY srs.conf /usr/local/srs/conf/srs.conf
CMD ["./objs/srs", "-c", "/usr/local/srs/conf/srs.conf"]


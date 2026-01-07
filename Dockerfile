ARG baseImg=arm64v8/gcc:15.2-trixie

FROM ${baseImg}

RUN apt-get update && \
    apt-get install -y \
    build-essential \
    make \
    git \
    wget \
    libssl-dev \
    zlib1g-dev \
    bzip2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ADD . /app

ENV DROPBEAR_VERSION=2024.86

# ENV LDFLAGS=-static-libgcc
# ENV CFLAGS="-ffunction-sections -fdata-sections"
# ENV LTM_CFLAGS=-Os

RUN ./configure --enable-static 
RUN make -j8 PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp" MULTI=1

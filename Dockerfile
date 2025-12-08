ARG build_arch=arm64v8  

FROM ${build_arch}/gcc

RUN apt-get update && \
    apt-get install -y \
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

# ENV LDFLAGS=-Wl,--gc-sections
# ENV CFLAGS="-ffunction-sections -fdata-sections"
# ENV LTM_CFLAGS=-Os

RUN ./configure --enable-static
RUN make -j8 PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp" MULTI=1

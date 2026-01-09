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
    autoconf \
    automake \
    libtool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone https://github.com/openssh/openssh-portable --depth=1
WORKDIR /app/openssh-portable

RUN autoreconf && \
    ./configure \
    --disable-server \
    --disable-strip \
    --disable-pkcs11 \
    --disable-security-key \
    --without-openssl \
    --without-zlib-version-check \
    --without-openssl-header-check \
    --with-sandbox=no \
    --with-pam=no \
    --with-selinux=no \
    --with-kerberos5=no \
    --with-libedit=no \
    --with-ldns=no \
    CC="gcc -static" \
    CFLAGS="-Os -ffunction-sections -fdata-sections -fno-exceptions -fno-rtti" \
    LDFLAGS="-static -Wl,--gc-sections -Wl,--strip-all" \
    LIBS="-static -lz -lcrypto -lssl"
    
RUN make -j8

WORKDIR /app

ADD . /app

ENV DROPBEAR_VERSION=2024.86

# ENV LDFLAGS=-static-libgcc
# ENV CFLAGS="-ffunction-sections -fdata-sections"
# ENV LTM_CFLAGS=-Os

RUN ./configure --enable-static 
RUN make -j8 PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp" MULTI=1

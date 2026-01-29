ARG baseImg=arm64v8/alpine:3.20

FROM ${baseImg}

RUN apk add --no-cache \
    bash \
    build-base \
    git \
    wget \
    autoconf \
    automake \
    libtool \
    pkgconf \
    coreutils \
    bzip2 \
    linux-headers \
    openssl-dev \
    openssl-libs-static \
    zlib-dev \
    zlib-static \
    perl \
    m4

WORKDIR /app

ENV TARGET=aarch64-alpine-linux-musl \
    CC="gcc -static" \
    CFLAGS="-Os -ffunction-sections -fdata-sections -fno-exceptions -fno-rtti" \
    LDFLAGS="-static -Wl,--gc-sections -Wl,--strip-all"

RUN git clone https://github.com/openssh/openssh-portable --depth=1
WORKDIR /app/openssh-portable

RUN autoreconf && \
    ./configure \
    --host=${TARGET} \
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
    CC="${CC}" \
    CFLAGS="${CFLAGS}" \
    LDFLAGS="${LDFLAGS}" \
    LIBS="-static -lz -lcrypto -lssl"
    
RUN make -j"$(nproc)"

WORKDIR /app

ADD . /app

ENV DROPBEAR_VERSION=2024.86

# ENV LDFLAGS=-static-libgcc
# ENV CFLAGS="-ffunction-sections -fdata-sections"
# ENV LTM_CFLAGS=-Os

RUN ./configure --host=${TARGET} --enable-static CC="${CC}" CFLAGS="${CFLAGS}" LDFLAGS="${LDFLAGS}"
RUN make -j"$(nproc)" PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp" MULTI=1

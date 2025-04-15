FROM arm32v7/gcc

RUN apt-get update && \
    apt-get install -y \
        make \
        git \
        wget \
        libssl-dev \
        zlib1g-dev \
        bzip2 \
        && rm -rf /var/lib/apt/lists/*

ENV DROPBEAR_VERSION=2024.86
RUN mkdir /usr/src/dropbear
WORKDIR /usr/src/dropbear
ADD . /usr/src/dropbear

RUN ./configure --enable-static && \
    make PROGRAMS="dropbear"

RUN mkdir /out

CMD ["dropbear", "-V"]

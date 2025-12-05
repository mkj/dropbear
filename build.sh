#!/bin/sh

set -e

arch=$1
if [ -z "$arch" ]; then
  arch="arm64"
fi

platform=""
dockername=""
dockerfile=""
distdir=""
if [ "$arch" = "arm64" ]; then
  platform="linux/arm64/v8"
  dockername="arm64v8-dropbear"
  dockerfile="Dockerfile-arm64"
  distdir="build/arm64"
elif [ "$arch" = "arm" ]; then
  platform="linux/arm/v7"
  dockername="arm32v7-dropbear"
  dockerfile="Dockerfile-arm"
  distdir="build/arm"
else
  echo "Unsupported architecture: $arch"
  exit 1
fi

echo "Building for architecture: $arch"
echo "Using platform: $platform"
echo "Using docker image name: $dockername"
echo "Using dockerfile: $dockerfile"
echo "Using distribution directory: $distdir"

mkdir -p $(pwd)/$distdir/bin
mkdir -p $(pwd)/$distdir/lib
mkdir -p $(pwd)/$distdir/include

docker build --platform=$platform -t $dockername -f $dockerfile .  
docker run -it --rm -v $(pwd)/build:/app/build $dockername cp ./dropbearmulti ./$distdir/bin/
docker run -it --rm -v $(pwd)/build:/app/build $dockername cp ./libtomcrypt/libtomcrypt.a ./$distdir/lib/

cp -r ./libtomcrypt/src/headers/* ./$distdir/include

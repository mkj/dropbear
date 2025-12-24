#!/bin/sh

set -e

arch=$1
if [ -z "$arch" ]; then
  arch="arm64"
fi

platform=""
dockername=""
docker_baseImg=""
distdir=""
if [ "$arch" = "arm64" ]; then
  platform="linux/arm64/v8"
  dockername="arm64v8-dropbear"
  docker_baseImg="arm64v8/gcc:15.2-trixie"
  distdir="build/arm64"
elif [ "$arch" = "arm" ]; then
  platform="linux/arm/v7"
  dockername="arm32v7-dropbear"
  docker_baseImg="arm32v7/gcc:11-bullseye"
  distdir="build/arm"
else
  echo "Unsupported architecture: $arch"
  exit 1
fi

echo "Building for architecture: $arch"
echo "Using platform: $platform"
echo "Using docker image name: $dockername"
echo "Using docker build architecture: $docker_build_arch"
echo "Using distribution directory: $distdir"

rm -rf "$distdir"

mkdir -p "$distdir/bin"
mkdir -p "$distdir/lib"
mkdir -p "$distdir/include"

docker build --platform=$platform -t $dockername  --build-arg baseImg=$docker_baseImg .
docker run -it --rm -v $(pwd)/build:/app/build $dockername cp ./dropbearmulti ./$distdir/bin/
docker run -it --rm -v $(pwd)/build:/app/build $dockername cp ./libtomcrypt/libtomcrypt.a ./$distdir/lib/

cp -r ./libtomcrypt/src/headers/* ./$distdir/include

cd $distdir/bin

ln -s dropbearmulti dropbear
ln -s dropbearmulti dbclient
ln -s dropbearmulti dropbearkey
ln -s dropbearmulti dropbearconvert
ln -s dropbearmulti scp

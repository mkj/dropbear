#!/bin/sh

set -e

hardware=$1
if [ -z "$hardware" ]; then
  hardware="arm64"
fi

platform=""
dockername=""
docker_baseImg=""
distdir=""
if [ "$hardware" = "arm64" ]; then
  # supported arm64-jetson arm64-spark
  platform="linux/arm64/v8"
  dockername="arm64v8-jetson-dropbear"
  docker_baseImg="arm64v8/ubuntu:22.04"
elif [ "$hardware" = "arm64-axis" ]; then
  platform="linux/arm64/v8"
  dockername="arm64v8-axis-dropbear"
  docker_baseImg="arm64v8/gcc:15.2-trixie"
elif [ "$hardware" = "arm" ]; then
  platform="linux/arm/v7"
  dockername="arm32v7-dropbear"
  docker_baseImg="arm32v7/gcc:11-bullseye"
else
  echo "Unsupported hardware: $hardware"
  exit 1
fi

distdir="build/$hardware"

echo "Building for hardware: $hardware"
echo "Using platform: $platform"
echo "Using docker image name: $dockername"
echo "Using docker build architecture: $docker_build_arch"
echo "Using distribution directory: $distdir"

rm -rf "$distdir"

mkdir -p "$distdir/bin"
mkdir -p "$distdir/lib"
mkdir -p "$distdir/include"

echo "docker build --platform=$platform -t $dockername  --build-arg baseImg=$docker_baseImg ."
docker build --platform=$platform -t $dockername  --build-arg baseImg=$docker_baseImg .

echo "docker run -it --rm -v $(pwd)/build:/app/build $dockername cp ./dropbearmulti ./$distdir/bin/"
docker run -it --rm -v $(pwd)/build:/app/build $dockername cp ./dropbearmulti ./$distdir/bin/

echo "docker run -it --rm -v $(pwd)/build:/app/build $dockername cp ./libtomcrypt/libtomcrypt.a ./$distdir/lib/"
docker run -it --rm -v $(pwd)/build:/app/build $dockername cp ./libtomcrypt/libtomcrypt.a ./$distdir/lib/

cp -r ./libtomcrypt/src/headers/* ./$distdir/include

cd $distdir/bin

ln -s dropbearmulti dropbear
ln -s dropbearmulti dbclient
ln -s dropbearmulti dropbearkey
ln -s dropbearmulti dropbearconvert
ln -s dropbearmulti scp

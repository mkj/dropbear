#!/bin/sh
docker build --platform=linux/arm/v7 -t  arm32v7-dropbear .  
docker run -it --rm -v $(pwd)/build:/out arm32v7-dropbear cp dropbear /out 

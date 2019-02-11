#!/bin/sh

docker build -t thunderclap-arm .
docker run -it --rm -v $(pwd):/build thunderclap-arm make -C /build TARGET=arm CC=arm-linux-gnueabihf-gcc-5 LD=arm-linux-gnueabihf-gcc-5 CROSS_USR=/usr

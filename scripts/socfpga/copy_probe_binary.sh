#!/bin/bash -e

SDROOT=$1

QEMU_TREE=$(realpath $(dirname $(realpath $0))/../../)

QEMU_BINARY=$QEMU_TREE/build-arm/test

pushd $QEMU_TREE
rm -rf linux-packages
mkdir linux-packages
cd linux-packages
apt download libgettextpo0:armhf libgettextpo-dev:armhf libglib2.0:armhf \
	libpcre3:armhf libpcre3-dev:armhf libpixman-1-0:armhf \
	libpixman-1-dev:armhf libelf1:armhf zlib1g:armhf zlib1g-dev:armhf
for f in $(ls *.deb); do
    echo "Extracting" $f "..."
    ar x $f
    tar xf data.tar.xz
done
cd ..
make -j4
popd

sudo mkdir -p $SDROOT/usr/local/bin
sudo cp -a $QEMU_BINARY $SDROOT/usr/local/bin/pcie-probe-software

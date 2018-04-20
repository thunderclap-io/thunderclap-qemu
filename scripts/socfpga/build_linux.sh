#!/bin/sh -e

COMPILER_FILE="gcc-linaro-7.2.1-2017.11-x86_64_arm-linux-gnueabihf"
COMPILER_URL="https://releases.linaro.org/components/toolchain/binaries/7.2-2017.11/arm-linux-gnueabihf/${COMPILER_FILE}.tar.xz"
CWD=$(pwd)
CPUS=8

KERNEL_BRANCH="socfpga-4.15"

echo "Fetching compiler..."
wget -c $COMPILER_URL
echo "Untarring compiler..."
tar xJf $COMPILER_FILE.tar.xz
export CROSS_COMPILE=$CWD/$COMPILER_FILE/bin/arm-linux-gnueabihf-

echo "Fetching Linux source..."
git clone https://github.com/altera-opensource/linux-socfpga
cd linux-socfpga
git checkout $KERNEL_BRANCH
export ARCH=arm
echo "Configuring Linux source..."
# may need to install ncurses-devel or ncurses-dev package for this step
make socfpga_defconfig
# change any options here
#make menuconfig
make zImage -j$CPUS
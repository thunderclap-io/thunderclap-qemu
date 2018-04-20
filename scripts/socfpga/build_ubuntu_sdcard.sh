#!/bin/bash -e

FPGA_DIR=$1
FPGA_PROJECT=$2
FPGA_HANDOFF_DIR=hps_isw_handoff
FPGA_BITFILE_RBF=$FPGA_DIR/output_files/$FPGA_PROJECT.rbf
SD_IMAGE=sdimage.img
ROOT_SIZE_MB=25000
SD_SIZE_MB=29000
echo $SCRIPT_PATH

DTB=socfpga_arria10_socdk_sdmmc.dtb

SCRIPT_NAME=$(readlink -f "$0")
SCRIPT_PATH=$(dirname "$SCRIPT_NAME")

$SCRIPT_PATH/fetch_ubuntu.sh

$SCRIPT_PATH/build_linux.sh

cp -a linux-socfpga/vmlinux zImage

$SCRIPT_PATH/make_uboot.sh $FPGA_PROJECT/$FPGA_HANDOFF_DIR

$SCRIPT_PATH/make_device_tree.sh $FPGA_DIR $FPGA_PROJECT.sopcinfo

cp -a $FPGA_DIR/$DTB $DTB	
cp -a $FPGA_BITFILE_RBF socfpga.rbf

echo "Building SD card image"
$SCRIPT_PATH/make_sdimage.py -f	\
	-P uboot_w_dtb-mkpimage.bin,num=3,format=raw,size=10M,type=A2 \
	-P mnt/2/*,num=2,format=ext3,size=$ROOT_SIZE_MB \
	-P zImage,socfpga.rbf,socfpga_arria10_socdk_sdmmc.dtb,num=1,format=vfat,size=500M \
	-s $SD_SIZE_MB \
	-n $SD_IMAGE

sudo umount mnt/1 mnt/2

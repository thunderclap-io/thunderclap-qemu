#!/bin/bash -e

FPGA_DIR=$1
FPGA_PROJECT=$2
FPGA_HANDOFF_DIR=hps_isw_handoff
FPGA_BITFILE_RBF=$FPGA_DIR/output_files/$FPGA_PROJECT.rbf
SD_IMAGE=sdimage.img
ROOT_SIZE_MB=1500
SD_SIZE_MB=2048
echo $SCRIPT_PATH

DTB=socfpga_arria10_socdk_sdmmc.dtb

SCRIPT_NAME=$(readlink -f "$0")
SCRIPT_PATH=$(dirname "$SCRIPT_NAME")

function ubuntu() {
	$SCRIPT_PATH/fetch_ubuntu.sh
	$SCRIPT_PATH/configure_networking.sh mnt/2/
}

function kernel() {
	$SCRIPT_PATH/build_linux.sh
}

function uboot() {
	$SCRIPT_PATH/make_uboot.sh $FPGA_DIR/$FPGA_HANDOFF_DIR
	cp -a bsp/uboot_w_dtb-mkpimage.bin .
}

function devicetree() {
	$SCRIPT_PATH/make_device_tree.sh $FPGA_DIR $FPGA_PROJECT.sopcinfo

	cp -a $FPGA_DIR/$DTB $DTB	
}

function bitfile() {
	$SCRIPT_PATH/make_bitfile.sh $FPGA_DIR $FPGA_PROJECT
	cp -a $FPGA_BITFILE_RBF socfpga.rbf
}

function sdimage() {

	echo "Building SD card image"
	sudo $SCRIPT_PATH/make_sdimage.py -f	\
		-P uboot_w_dtb-mkpimage.bin,num=3,format=raw,size=10M,type=A2 \
		-P mnt/2/*,num=2,format=ext3,size=${ROOT_SIZE_MB}M \
		-P zImage,socfpga.rbf,socfpga_arria10_socdk_sdmmc.dtb,num=1,format=vfat,size=500M \
		-s ${SD_SIZE_MB}M \
		-n $SD_IMAGE

}


function tidy() {
	sudo umount mnt/1 mnt/2
}


ubuntu
kernel
uboot
devicetree
bitfile
sdimage
tidy

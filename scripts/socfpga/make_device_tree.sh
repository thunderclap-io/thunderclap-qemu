#!/bin/bash -e

FPGA_TREE=$1
SOPCINFO=$2
DTB=socfpga_arria10_socdk_sdmmc.dtb

DTS=${DTB%.dtb}.dts

echo "Building Linux device tree..."
pushd $FPGA_TREE
echo "...generating DTS from sopcinfo"
sopc2dts --input $SOPCINFO --output $DTS  --board hps_a10_common_board_info.xml \
	--board hps_a10_devkit_board_info.xml \
	--board ghrd_10as066n2_board_info.xml \
	--bridge-removal all --clocks
echo "...compiling DTS to DTB"
dtc -f -I dts -O dtb -o $DTB $DTS
popd
echo "...copying DTB to working directory"
cp -a $FPGA_TREE/$DTB $DTB

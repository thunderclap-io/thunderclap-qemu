#!/bin/bash -e

FPGA_TREE=$1
SOPCINFO=$2
DTB=$3

DTS=${DTB%.dtb}.dts

echo "Building Linux device tree..."
pushd $FPGA_TREE
sopc2dts --input $SOPCINFO --output $DTS  --board hps_a10_common_board_info.xml \
	--board hps_a10_devkit_board_info.xml \
	--board ghrd_10as066n2_board_info.xml \
	--bridge-removal all --clocks
dtc -f -I dts -O dtb -o $DTB $DTS
popd
cp -a $FPGA_TREE/$DTB $DTB

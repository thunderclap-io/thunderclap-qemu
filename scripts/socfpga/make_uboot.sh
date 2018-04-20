#!/bin/sh -e

# build a uboot and preloader image, using the hps_isw_handoff tree output by the FPGA build

# parameter = location of the hps_isw_handoff tree, contains emif.xml and hps.xml
FPGA_HANDOFF_DIR="$1"
# BSP directory to generate
BSP_DIR="bsp"

bsp-create-settings --type uboot \
	--preloader-settings-dir $FPGA_HANDOFF_DIR --bsp-dir $BSP_DIR --settings $BSP_DIR/settings.bsp
make -C $BSP_DIR

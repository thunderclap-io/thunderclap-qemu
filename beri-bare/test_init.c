/*-
 * Copyright (c) 2012 Jonathan Woodruff
 * Copyright (c) 2012 Simon W. Moore
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * @BERI_LICENSE_HEADER_START@
 *
 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  BERI licenses this
 * file to you under the BERI Hardware-Software License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *   http://www.beri-open-systems.org/legal/license-1-0.txt
 *
 * Unless required by applicable law or agreed to in writing, Work distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @BERI_LICENSE_HEADER_END@
 */

#include "parameters.h"

#include "pcie.h"
#include "pciefpga.h"
#include "beri-io.h"

#include <stdint.h>
#include <stdbool.h>

#define BUTTONS (0x900000007F009000ULL)

#define IO_RD_BYTE(x) (*(volatile unsigned char*)(x))
#define IO_RD(x) (*(volatile unsigned long long*)(x))
#define IO_RD32(x) (*(volatile int*)(x))
#define IO_WR(x, y) (*(volatile unsigned long long*)(x) = y)
#define IO_WR_BYTE(x, y) (*(volatile unsigned char*)(x) = y)


void writeUARTChar(char c)
{
	//Code for SOPC Builder serial output
	while ((IO_RD32(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE)+4) &
	    0xFFFF) == 0) {
		asm("add $v0, $v0, $0");
	}
	//int i;
	//for (i=0;i<10000;i++);
	IO_WR_BYTE(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE), c);
}

void writeString(char* s)
{
	while(*s)
	{
		writeUARTChar(*s);
		++s;
	}
}

void writeHex(unsigned long long n)
{
	unsigned int i;
	for(i = 0;i < 16; ++i)
	{
		unsigned long long hexDigit = (n & 0xF000000000000000L) >> 60L;
//		unsigned long hexDigit = (n & 0xF0000000L) >> 28L;
		char hexDigitChar = (hexDigit < 10) ? ('0' + hexDigit) : ('A' + hexDigit - 10);
		writeUARTChar(hexDigitChar);
		n = n << 4;
	}
}

void writeDigit(unsigned long long n)
{
	unsigned int i;
	unsigned int top;
	char tmp[17];
	char str[17];
	
	for(i = 0;i < 17; ++i) str[i] = 0;
	i = 0;
	while(n > 0) {
		tmp[i] = '0' + (n % 10);
		n /= 10;
		i = i + 1;
	}
	i--;
	top = i;
	while(i > 0) {
		str[top - i] = tmp[i];
		i--;
	}
	str[top] = tmp[0];
	writeString(str);
}

char readUARTChar()
{
	int i;
	char out;
	i = IO_RD32(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE));
	while((i & 0x00800000) == 0)
	{
		i = IO_RD32(MIPS_PHYS_TO_UNCACHED(CHERI_JTAG_UART_BASE));
	}
	
	i = i >> 24;
	out = (char)i;
	return out;
}


/* ************************************************************************** */
// Helper functions to access I2C
// base address
#define HDMI_TX_RESET_N_BASE (0x900000007F00B080ULL)
#define I2C_BASE (0x900000007F00B000ULL)

// I2C device number of IT6613 HDMI chip
// note: the device number is the upper 7-bits and bit 0 is left to indicate
//       read or write
#define HDMI_I2C_DEV  0x98

// clock scale factor to get target 100kHz:  scale = system_clock_kHz/(4*100)
#define I2C_CLK_SCALE 1250

void reset_hdmi_chip(void)
{
	IO_WR_BYTE(HDMI_TX_RESET_N_BASE, 0);
	writeString("Reset HDMI chip");  // debug output and delay all in one...
	IO_WR_BYTE(HDMI_TX_RESET_N_BASE, 1);
}

void
i2c_write_reg(int regnum, int data)
{
	IO_WR_BYTE(I2C_BASE + regnum, data);
}


int
i2c_read_reg(int regnum)
{
	return IO_RD_BYTE(I2C_BASE + regnum);
}


void
i2c_write_clock_scale(int scale)  // scale is 16-bit number
{
	i2c_write_reg(0, scale & 0xff);
	i2c_write_reg(1, scale >> 8);
}


int
i2c_read_clock_scale(void)
{
	return i2c_read_reg(0) | (i2c_read_reg(1)<<8);
}


void i2c_write_control(int d) { i2c_write_reg(2, d); }
void i2c_write_tx_data(int d) { i2c_write_reg(3, d); }
void i2c_write_command(int d) { i2c_write_reg(4, d); }

int i2c_read_control() { return i2c_read_reg(2); }
int i2c_read_rx_data() { return i2c_read_reg(3); }
int i2c_read_status () { return i2c_read_reg(4); }
int i2c_read_tx_data() { return i2c_read_reg(5); }
int i2c_read_command() { return i2c_read_reg(6); }


int
i2c_write_data_command(int data, int command)
{
	int t, sr;
	//writeString("i2c write data=");
	//writeHex(data);
	//writeString(", command=");
	//writeHex(command);
	//writeString("\n");
	i2c_write_tx_data(data); // device num + write (=0) bit
	i2c_write_command(command);
	sr = i2c_read_status();
	if((sr & 0x02)==0){
		//writeString("ERROR - I2C should be busy but isn't - sr=");
		//writeHex(sr);
		//writeString("\n");
	}

	for(t=100*I2C_CLK_SCALE; (t>0) && ((sr & 0x02)!=0); t--)
		sr = i2c_read_status();
	/*
	if(t==0)
		writeString("WRITE TIME OUT\n");
	if((sr & 0x02)!=0)
		writeString("ERROR - transfer is not complete\n");
	if((sr&0x80)!=0)
		writeString("ERROR - no ack received\n");
	*/
	return sr;
}

int
hdmi_read_reg(int i2c_addr)
{
	int t, sr;
	// write data: (7-bit address, 1-bit 0=write)
	// command: STA (start condition, bit 7) + write (bit 4)
	sr = i2c_write_data_command(HDMI_I2C_DEV, 0x90);
	sr = i2c_write_data_command(i2c_addr, 0x10);

	// now start the read (with STA and WR bits)
	sr = i2c_write_data_command(HDMI_I2C_DEV | 0x01, 0x90);
	// set RD bit, set ACK to '1' (NACK), set STO bit
	i2c_write_command(0x20 | 0x08 | 0x40);

	for(t=100*I2C_CLK_SCALE,sr=2; (t>0) && ((sr & 0x02)!=0); t--)
		sr = i2c_read_status();
	if(t==0) {
		writeString("READ TIME OUT - sr=");
		writeHex(sr);
		writeString("\n");
	}
	/*
	if((sr & 0x02)!=0)
		writeString("ERROR - transfer is not complete\n");
	if((sr&0x80)==0)
		writeString("ERROR - no nack received\n");
	*/
	return i2c_read_rx_data();
}

void
hdmi_write_reg(int i2c_addr, int i2c_data_byte)
{
	int sr;
	// write data: (7-bit address, 1-bit 0=write)
	// command: STA (start condition, bit 7) + write (bit 4)
	sr = i2c_write_data_command(HDMI_I2C_DEV, 0x90);
	// command=write
	sr = i2c_write_data_command(i2c_addr, 0x10);
	// command=write+STO (stop)
	sr = i2c_write_data_command(i2c_data_byte & 0xff, 0x50);
	/*
	writeString("i2c hdmi write addr=");
	writeHex(i2c_addr);
	writeString(", data=");
	writeHex(i2c_data_byte);
	writeString("\n");
	*/
}

void
configure_hdmi(void)
{
	// set clock scale factor = system_clock_freq_in_Khz / 400
	{
		int j;
		writeString("Setting clock_scale to 0x");
		writeHex(I2C_CLK_SCALE);
		writeString("\n");
		i2c_write_clock_scale(I2C_CLK_SCALE);
		j = i2c_read_clock_scale();
		writeString("clock scale = 0x");
		writeHex(j);
		writeString("\n");
		if(j==I2C_CLK_SCALE)
			writeString(" - passed\n");
		else
			writeString(" - FAILED\n");

		hdmi_write_reg(0x0f, 0); // switch to using lower register bank (needed after a reset?)

		j = hdmi_read_reg(1);
		if(j==0xca)
			writeString("Correct vendor ID\n");
		else {
			writeString("FAILED - Vendor ID=0x");
			writeHex(j);
			writeString(" but should be 0xca\n");
		}

		j = hdmi_read_reg(2) | ((hdmi_read_reg(3) & 0xf)<<8);
		if(j==0x613)
			writeString("Correct device ID\n");
		else {
			writeString("FAILED - Device ID=0x");
			writeHex(j);
			writeString(" but should be 0x613\n");
		}
	}

	// the following HDMI sequence is based on Chapter 2 of
	// the IT6613 Programming Guide

	// HDMI: reset internal circuits via its reg04 register
	hdmi_write_reg(4, 0xff);
	hdmi_write_reg(4, 0x00); // release resets
	// hdmi_write_reg(4, 0x1d); - from reg dump

	// HDMI: enable clock ring
	hdmi_write_reg(61, 0x10);	// seems to read as 0x30 on "correct" version?

	// HDMI: set default DVI mode
	{
		int reg;
		for(reg=0xc0; reg<=0xd0; reg++)
			hdmi_write_reg(reg, 0x00);
	}
	// setting from reg dump - makes any sense?
	hdmi_write_reg(0xc3, 0x08);

	// blue screen:
	// hdmi_write_reg(0xc1, 2);

	// HDMI: write protection of C5 register?	needed?
	hdmi_write_reg(0xf8, 0xff);

	// HDMI: disable all interrupts via mask bits
	hdmi_write_reg(0x09, 0xff);
	hdmi_write_reg(0x0a, 0xff);
	hdmi_write_reg(0x0b, 0xff);
	// ...and clear any pending interrupts
	hdmi_write_reg(0x0c, 0xff);
	hdmi_write_reg(0x0d, 0xff);

	// setup interrupt status reg as per reg dump
	// hdmi_write_reg(0x0e, 0x6e);
	hdmi_write_reg(0x0e, 0x00);	// SWM: better to leave as zero?


	// HDMI: set VIC=3, ColorMode=0, Bool16x9=1, ITU709=0
	// HDMI: set RGB444 mode
	//	hdmi_write_reg(0x70, 0x08); // no input data formatting, but sync embedded
	hdmi_write_reg(0x70, 0x0); // no input data formatting, but sync embedded
	hdmi_write_reg(0x72, 0); // no input data formatting
	hdmi_write_reg(0x90, 0); // no sync generation

	{
		int sum = 0;
		// HDMI: construct AVIINFO (video frame information)
		hdmi_write_reg(0x0f, 1); // switch to using upper register bank
		/*
		if(hdmi_read_reg(0x0f)!=1)
			writeString("ASSERTION ERROR: not using correct register bank (see reg 0x0f)\n");
		*/
		hdmi_write_reg(0x58, 0x10); //=0 for DVI mode	 - (1<<4) // AVIINFO_DB1 = 0?
		sum += 0x10;
			//		hdmi_write_reg(0x59, 8 | (2<<4)); // AVIINFO_DB2 = 8 | (!b16x9)?(1<<4):(2<<4)
			//		sum += (8 | (2<<4));
		hdmi_write_reg(0x59, 0x68); // AVIINFO_DB2 = from reg dump
		sum += 0x68;
		hdmi_write_reg(0x5a, 0); // AVIINFO_DB3 = 0
		hdmi_write_reg(0x5b, 3); // AVIINFO_DB4 = VIC = 3
		sum +=3;
		hdmi_write_reg(0x5c, 0); // AVIINFO_DB5 = pixelrep & 3 = 0
		// 0x5d = checksum - see below
		hdmi_write_reg(0x5e, 0); // AVIINFO_DB6
		hdmi_write_reg(0x5f, 0); // AVIINFO_DB7
		hdmi_write_reg(0x60, 0); // AVIINFO_DB8
		hdmi_write_reg(0x61, 0); // AVIINFO_DB9
		hdmi_write_reg(0x62, 0); // AVIINFO_DB10
		hdmi_write_reg(0x63, 0); // AVIINFO_DB11
		hdmi_write_reg(0x64, 0); // AVIINFO_DB12
		hdmi_write_reg(0x65, 0); // AVIINFO_DB13
 		writeString("check: VIC = 0x");
		writeHex(hdmi_read_reg(0x5b));
		writeString("\n");
		// from docs:		hdmi_write_reg(0x5d, - (sum + 0x82 + 2 + 0x0d));
		// from Teraic code: hdmi_write_reg(0x5d, -sum - (2 + 1 + 13));
		// from reg dump:
		hdmi_write_reg(0x5d, 0xf4);
		writeString("check: checksum = 0x");
		writeHex(hdmi_read_reg(0x5b));
		writeString("\n");
	}
	hdmi_write_reg(0x0f, 0); // switch to using lower register bank
	hdmi_write_reg(0xcd, 3); // enable avi information packet

	// unmute screen? - correct?
	//hdmi_write_reg(0xc1, 0x41);
	hdmi_write_reg(0xc1, 0x00);

	// disable audio
	hdmi_write_reg(0xe0, 0x08);
	// needed? - part of audio format...
	hdmi_write_reg(0xe1, 0x0);

	writeString("Completed HDMI initialisation\n");
	/*
	{
		int reg;
		hdmi_write_reg(0x0f, 0); // switch to using lower register bank
		for(reg=0; reg<0xff; reg++)
			alt_printf("reg[%x] = %x\n",reg,hdmi_read_reg(reg));
		hdmi_write_reg(0x0f, 1); // switch to using upper register bank
		for(reg=0; reg<0xff; reg++)
			alt_printf("reg[b1 %x] = %x\n",reg,hdmi_read_reg(reg));
		hdmi_write_reg(0x0f, 0); // switch to using lower register bank
	}
	*/
}

void
brute_force_write_seq(void)
{

	// set clock scale factor = system_clock_freq_in_Khz / 400
	{
		int j;
		writeString("Setting clock_scale to 0x");
		writeHex(I2C_CLK_SCALE);
		writeString("\n");
		i2c_write_clock_scale(I2C_CLK_SCALE);
		j = i2c_read_clock_scale();
		writeString("clock scale = 0x");
		writeHex(j);
		if(j==I2C_CLK_SCALE)
			writeString(" - passed\n");
		else
			writeString(" - FAILED\n");

		hdmi_write_reg(0x0f, 0); // switch to using lower register bank (needed after a reset?)

		j = hdmi_read_reg(1);
		if(j==0xca)
			writeString("Correct vendor ID\n");
		else {
			writeString("FAILED - Vendor ID=0x");
			writeHex(j);
			writeString(" but should be 0xca\n");
		}

		j = hdmi_read_reg(2) | ((hdmi_read_reg(3) & 0xf)<<8);
		if(j==0x613)
			writeString("Correct device ID\n");
		else {
			writeString("FAILED - Device ID=0x");
			writeHex(j);
			writeString(" but should be 0x613\n");
		}
	}

	hdmi_write_reg(0x5, 0x0);
	hdmi_write_reg(0x4, 0x3d);
	hdmi_write_reg(0x4, 0x1d);
	hdmi_write_reg(0x61, 0x30);
	hdmi_write_reg(0x9, 0xb2);
	hdmi_write_reg(0xa, 0xf8);
	hdmi_write_reg(0xb, 0x37);
	hdmi_write_reg(0xf, 0x0);
	hdmi_write_reg(0xc9, 0x0);
	hdmi_write_reg(0xca, 0x0);
	hdmi_write_reg(0xcb, 0x0);
	hdmi_write_reg(0xcc, 0x0);
	hdmi_write_reg(0xcd, 0x0);
	hdmi_write_reg(0xce, 0x0);
	hdmi_write_reg(0xcf, 0x0);
	hdmi_write_reg(0xd0, 0x0);
	hdmi_write_reg(0xe1, 0x0);
	hdmi_write_reg(0xf, 0x0);
	hdmi_write_reg(0xf8, 0xc3);
	hdmi_write_reg(0xf8, 0xa5);
	hdmi_write_reg(0x22, 0x60);
	hdmi_write_reg(0x1a, 0xe0);
	hdmi_write_reg(0x22, 0x48);
	hdmi_write_reg(0xf8, 0xff);
	hdmi_write_reg(0x4, 0x1d);
	hdmi_write_reg(0x61, 0x30);
	hdmi_write_reg(0xc, 0xff);
	hdmi_write_reg(0xd, 0xff);
	hdmi_write_reg(0xe, 0xcf);
	hdmi_write_reg(0xe, 0xce);
	hdmi_write_reg(0x10, 0x1);
	hdmi_write_reg(0x15, 0x9);
	hdmi_write_reg(0xf, 0x0);
	hdmi_write_reg(0x10, 0x1);
	hdmi_write_reg(0x15, 0x9);
	hdmi_write_reg(0x10, 0x1);
	hdmi_write_reg(0x11, 0xa0);
	hdmi_write_reg(0x12, 0x0);
	hdmi_write_reg(0x13, 0x20);
	hdmi_write_reg(0x14, 0x0);
	hdmi_write_reg(0x15, 0x3);
	hdmi_write_reg(0x10, 0x1);
	hdmi_write_reg(0x15, 0x9);
	hdmi_write_reg(0x10, 0x1);
	hdmi_write_reg(0x11, 0xa0);
	hdmi_write_reg(0x12, 0x20);
	hdmi_write_reg(0x13, 0x20);
	hdmi_write_reg(0x14, 0x0);
	hdmi_write_reg(0x15, 0x3);
	hdmi_write_reg(0x10, 0x1);
	hdmi_write_reg(0x15, 0x9);
	hdmi_write_reg(0x10, 0x1);
	hdmi_write_reg(0x11, 0xa0);
	hdmi_write_reg(0x12, 0x40);
	hdmi_write_reg(0x13, 0x20);
	hdmi_write_reg(0x14, 0x0);
	hdmi_write_reg(0x15, 0x3);
	hdmi_write_reg(0x10, 0x1);
	hdmi_write_reg(0x15, 0x9);
	hdmi_write_reg(0x10, 0x1);
	hdmi_write_reg(0x11, 0xa0);
	hdmi_write_reg(0x12, 0x60);
	hdmi_write_reg(0x13, 0x20);
	hdmi_write_reg(0x14, 0x0);
	hdmi_write_reg(0x15, 0x3);
	hdmi_write_reg(0x4, 0x1d);
	hdmi_write_reg(0x61, 0x30);
	hdmi_write_reg(0xf, 0x0);
	hdmi_write_reg(0xc1, 0x41);
	hdmi_write_reg(0xf, 0x1);
	hdmi_write_reg(0x58, 0x10);
	hdmi_write_reg(0x59, 0x68);
	hdmi_write_reg(0x5a, 0x0);
	hdmi_write_reg(0x5b, 0x3);
	hdmi_write_reg(0x5c, 0x0);
	hdmi_write_reg(0x5e, 0x0);
	hdmi_write_reg(0x5f, 0x0);
	hdmi_write_reg(0x60, 0x0);
	hdmi_write_reg(0x61, 0x0);
	hdmi_write_reg(0x62, 0x0);
	hdmi_write_reg(0x63, 0x0);
	hdmi_write_reg(0x64, 0x0);
	hdmi_write_reg(0x65, 0x0);
	hdmi_write_reg(0x5d, 0xf4);
	hdmi_write_reg(0xf, 0x0);
	hdmi_write_reg(0xcd, 0x3);
	hdmi_write_reg(0xf, 0x0);
	hdmi_write_reg(0xf, 0x1);
	hdmi_write_reg(0xf, 0x0);
	hdmi_write_reg(0x4, 0x1d);
	hdmi_write_reg(0x70, 0x0);
	hdmi_write_reg(0x72, 0x0);
	hdmi_write_reg(0xc0, 0x0);
	hdmi_write_reg(0x4, 0x15);
	hdmi_write_reg(0x61, 0x10);
	hdmi_write_reg(0x62, 0x18);
	hdmi_write_reg(0x63, 0x10);
	hdmi_write_reg(0x64, 0xc);
	hdmi_write_reg(0x4, 0x15);
	hdmi_write_reg(0x4, 0x15);
	hdmi_write_reg(0xc, 0x0);
	hdmi_write_reg(0xd, 0x40);
	hdmi_write_reg(0xe, 0x1);
	hdmi_write_reg(0xe, 0x0);
	hdmi_write_reg(0xf, 0x0);
	hdmi_write_reg(0x61, 0x0);
	hdmi_write_reg(0xf, 0x0);
	hdmi_write_reg(0xc1, 0x40);
	hdmi_write_reg(0xc6, 0x3);
}
/* ********************************************************************* */

int
wait_for_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{
	volatile PCIeStatus pciestatus;
	volatile TLPQuadWord pciedata;
	volatile int ready;
	int i = 0; // i is "length of TLP so far received in doublewords.

	do {
		ready = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_READY);
	} while (ready == 0);

	do {
		pciestatus.word = IORD64(PCIEPACKETRECEIVER_0_BASE,
			PCIEPACKETRECEIVER_STATUS);
		pciedata = IORD64(PCIEPACKETRECEIVER_0_BASE, PCIEPACKETRECEIVER_DATA);
		tlp[i++] = pciedata;
		if ((i * 8) > tlp_len) {
			return -1;
		}
	} while (!pciestatus.bits.endofpacket);

	return (i * 8);
}

/* tlp is a pointer to the tlp, tlp_len is the length of the tlp in bytes. */
/* returns 0 on success. */
int
send_tlp(volatile TLPQuadWord *tlp, int tlp_len)
{
	int quad_word_index;
	volatile PCIeStatus statusword;

	// Stops the TX queue from draining whilst we're filling it.
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 0);

	// round up to a whole number of words
	for (quad_word_index = 0; quad_word_index < ((tlp_len+7) / 8);
			++quad_word_index) {
		statusword.word = 0;
		statusword.bits.startofpacket = (quad_word_index == 0);
		statusword.bits.endofpacket =
			((quad_word_index + 1) >= ((tlp_len+7) / 8));

		// Write status word.
		IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_STATUS,
			statusword.word);
		// Write data
		IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_DATA,
			tlp[quad_word_index]);
	}
	// Release queued data
	IOWR64(PCIEPACKETTRANSMITTER_0_BASE, PCIEPACKETTRANSMITTER_QUEUEENABLE, 1);

	return 0;
}

static inline void
create_config_completion_header(volatile TLPDoubleWord *tlp,
	enum tlp_direction direction, uint16_t completer_id,
	enum TLPCompletionStatus completion_status, uint16_t requester_id,
	uint8_t tag)
{
	// Clear buffer. If passed in a buffer that's too short, this might be an
	// exploit?
	tlp[0] = 0;
	tlp[1] = 0;
	tlp[2] = 0;

	volatile struct TLP64DWord0 *header0 = (volatile struct TLP64DWord0 *)(tlp);
	header0->fmt = ((direction == TLPD_READ) ?
		TLPFMT_3DW_DATA : TLPFMT_3DW_NODATA);
	header0->type = CPL;
	header0->length = ((direction == TLPD_READ) ? 1 : 0);

	volatile struct TLP64CompletionDWord1 *header1 =
		(volatile struct TLP64CompletionDWord1 *)(tlp) + 1;
	header1->completer_id = completer_id;
	header1->status = completion_status;
	header1->bytecount = 4;

	volatile struct TLP64CompletionDWord2 *header2 =
		(volatile struct TLP64CompletionDWord2 *)(tlp) + 2;
	header2->requester_id = requester_id;
	header2->tag = tag;
}

volatile uint8_t *led_phys_mem;

void
initialise_leds()
{
#define LED_BASE		(UNCACHED_BASE + 0x7F006000LL)
#define LED_LEN			0x1

		led_phys_mem = (uint8_t *)LED_BASE;

#undef LED_LEN
#undef LED_BASE
}

static inline void
write_leds(uint8_t data)
{
	*led_phys_mem = ~data;
}


int
test()
{
	writeString("PCIE Test run. LEDs count up for each packet.\n");

	initialise_leds();

	int i, tlp_in_len = 0, send_length, send_result;
	enum tlp_direction dir;
	uint16_t device_id, requester_id;
	uint64_t req_addr;

	TLPDoubleWord tlp_in[64], tlp_out[64];
	TLPDoubleWord *tlp_out_body = (tlp_out + 3);
	TLPQuadWord *tlp_in_quadword = (TLPQuadWord *)tlp_in;
	TLPQuadWord *tlp_out_quadword = (TLPQuadWord *)tlp_out;

	struct TLP64DWord0 *dword0 = (struct TLP64DWord0 *)tlp_in;
	struct TLP64RequestDWord1 *request_dword1 =
		(struct TLP64RequestDWord1 *)(tlp_in + 1);
	struct TLP64ConfigRequestDWord2 *config_request_dword2 =
		(struct TLP64ConfigRequestDWord2 *)(tlp_in + 2);

	struct TLP64ConfigReq *config_req = (struct TLP64ConfigReq *)tlp_in;
	struct TLP64RequestDWord1 *req_bits = &(config_req->req_header);

	int received_count = 0;
	write_leds(received_count);

	tlp_in[0] = 0xDEADBEE0;
	tlp_in[1] = 0xDEADBEE1;
	tlp_in[2] = 0xDEADBEE2;
	tlp_in[3] = 0xDEADBEE3;

	for (i = 0; i < 64; ++i) {
		tlp_out[i] = 0;
	}

	while (1) {
		tlp_in_len = wait_for_tlp(tlp_in_quadword, sizeof(tlp_in));
		++received_count;
		write_leds(received_count);

		dir = ((dword0->fmt & 2) >> 1);

		switch (dword0->type) {
		case CFG_0:
			requester_id = request_dword1->requester_id;
			device_id = config_request_dword2->device_id;
			req_addr = config_request_dword2->ext_reg_num;
			req_addr = (req_addr << 6) | config_request_dword2->reg_num;

			if (dir == TLPD_READ) {
				send_length = 16;
				tlp_out_body[0] = 0;
			} else {
				send_length = 12;
			}

			create_config_completion_header(
				tlp_out, dir, device_id, TLPCS_SUCCESSFUL_COMPLETION,
				requester_id, req_bits->tag);

			send_result = send_tlp(tlp_out_quadword, send_length);
		default:
			break;
		}
	}

	return 0;
}

# Thunderclap I/O security research platform

Thunderclap is a hardware/software platform for research into the security of computer peripherals and their interaction with operating systems.
See https://thunderclap.io/ for more details.

This repository contains the software component, which implements a model of
the Intel 82574L ethernet card (the common 'E1000' type) using an extremely
cut-down version of the QEMU system emulator.

## Variations

The current supported flow is to build a binary to run on Ubuntu on the
Arria 10 FPGA's Arm Cortex A9 Hard Processor System (HPS).  Apart from the
memory-mapped I/O port which allows us to send and receive PCIe packets,
this is very similar to other Ubuntu/Arm platforms (eg Raspberry Pi).

We have been through a number of different iterations which we no longer
support but remain in the codebase. They were relevant as we developed the
work in the Thunderclap paper.

Previously we ran on the [BERI CPU](http://www.beri-cpu.org) (which
implements the 64-bit MIPS ISA) on Stratix V CPUs - this is largely
deprecated, although the build infrastructure remains.  We have retained the
[previous version of this file](README-legacy.md) for reference, which also
contains more detail of the previous non-Docker build.

We also have a backend that runs against a Postgres database of a trace of
PCIe TLPs from a real 82574L, which we used for the initial bringup (in
particular, debugging endian issues on the BERI big-endian MIPS).

Some of our earliest work was done on an Intel/Altera NIOS-II soft-core,
running without an operating system.  This was not able to run QEMU, but did
achieve some of our more basic attacks.

## Building for ARM

As we need an Arm cross-build environment with several package dependencies,
the build is somewhat complex.  However we have wrapped it up using Docker
which should make it easier:

* [Install Docker](https://docs.docker.com/install/) on your machine (Linux/Mac/Windows).
* Run `./make-docker.sh`  from a shell prompt
* The output binary is called `thunderclap` in the top level of the source tree

## Running Attacks

To run an attack, the Thunderclap binary must be copied onto the FPGA's
storage, either by mounting the SD card in another machine, or using SSH by
plugging in ethernet to the FPGA board's own HPS ethernet port.
(You should be able to `ifconfig`/`dhclient` the Arm's ethernet like any other
Linux machine. Boards often have additional ports designed to be driven by
FPGA logic alone - we don't use these.)

Run the binary on the FPGA, and then power up the victim PC and let it boot
with the Thunderclap PCIe NIC.  Alternatively mount the FPGA in a
PCIe/Thunderbolt dock and hotplug the dock into the victim.

We have mostly performed attacks by printing data to the console, although
the FPGA is able to store data on the SD card or exfiltrate it over its own
ethernet port.

## Writing Attacks

Attack code should be placed in `attacks.c` in the system root.
This uses an embryonic hook system.
At the moment, the only hook is

```c
void register_pre_xmit_hook(OperateOnDescriptor loop_body, void (*done)())
```

This takes two arguments: a callback to be called for each entry in the simulated NIC's transmit ring, and a function pointer to be called once the callback has been called for each entry in the ring.
Currently, it is called from a function with `__attribute__((constructor))` in `attacks.c`, to ensure that it is called before `main` is run.
Only one callback can be assigned for each hook.
Calling a `register` function again will overwrite the existing hook.

`OperateOnDescriptor` function pointers take two pointers, an `E1000ECore *`, and a `ConstDescriptorP`.
The `E1000ECore` is QEMU's internal model of the state of an E1000E. It is defined in `hw/net/e1000e_core.h`.
You shouldn't need to interact with its fields too often, but the structure is required as an argument to many functions.

`ConstDescriptorP` is a const pointer to a const `Descriptor`:

```c
struct Descriptor {
	enum DescriptorType type;
	uint64_t buffer_addr;
	uint16_t length;
};

enum DescriptorType { DT_TRANSMIT, DT_RECEIVE };
```

This is a generalised representation of e1000e transmit and receive descriptors.
Some descriptors have more metadata than is contained in the representation, but this has proved unnecessary for attacks so far, so we have not included it.

## Interacting with PCIe

We have endeavoured to make the PCIe library as user-friendly as possible.
There is, however, only so much lipstick that can be put on a pig.
For sophisticated work, it is likely that you will have to use some of the more low-level functions in consultation with the PCIe Manual.

The functions for interacting with PCIe are in `pcie.h`.

High-Level Functions
--------------------

We provide a number of functions for interacting with PCIe that impose artificial, blocking, in-order semantics.
This is a natural way of programming in C, but not reflective of how PCIe works in practice.

### Read Functions

These return an `enum dma_read_response`, defined as

```c
enum dma_read_response {
	DRR_SUCCESS = 0,
	DRR_UNSUPPORTED_REQUEST,
	DRR_NO_RESPONSE
};
```

Success and Unsupported Request refer to the corresponding codes in the PCIe spec. No response means that the function timed out before receiving a response from the host.
This is currently set fairly arbitrarily at 10,000 polls of the host.

```c
enum dma_read_response
perform_dma_read(uint8_t* buf, uint16_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address);
```

Attempts a DMA read of host memory.
Can't read more than 512 bytes at a time.
The first two arguments define a buffer and its length in bytes.
`requester_id` is the requester id to be used for the transaction.
When writing an attack from the NIC-based platform, this will most often be
`core->owner->devfn`, where `core` is an `E1000ECore *`.
Tag is a per-function virtual-channel identifier.
The e1000e uses a different tag to refer requests of different purposes, so there is one for read RX ring, for example, and another for read TX ring, and so on.
Any value from 0 to 255 is probably fine: we typically use 8, and don't have issues.
The specific meanings of each tag can be found in the Intel 82754L datasheet.
Address is the IO Virtual Address of the memory area to be read.

```c
enum dma_read_response
perform_translated_dma_read(uint8_t* buf, uint16_t length,
	uint16_t requester_id, uint8_t tag, uint64_t address);
```

Attempts a DMA read with the `Address Translated` bit set.
Unless you know you know you want this, you probably don't want this.
Look up ATS, Address Translation Services, in the PCIe specification.


```c
enum dma_read_response
perform_dma_long_read(uint8_t* buf, uint64_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address);
```

The same as `perform_dma_read`, but fragments the read into chunks, for if you are reading more than 512 bytes at a time.

### Write Functions

```c
int
perform_dma_write(const uint8_t* buf, int16_t length, uint16_t requester_id,
	uint8_t tag, uint64_t address)
```

This has the same arguments as `perform_translated_dma_read` above, except the buffer contains the data to be written to an area in host memory.
Not capable of writing more than 128 bytes at a time.
Always returns 0.
PCIe writes are 'non-posted', meaning that they do not ever get a response, so if you want to be sure that this has worked, perform a read of the same memory location.

### Low-level Functions

If you wish to do something more complex than the DMA operations specified above, or be able to respond to requests made by the host, you need to use some of the lower-level functionality of the Thunderclap interface.

The fundamental datatype used by the core of the library is RawTLP:

```c
struct RawTLP {
	int header_length;
	TLPDoubleWord *header;
	int data_length;
	TLPDoubleWord *data;
};
```

This uses length fields in bytes, and contains pointers to the start of header and data sections of TLPs, which may be of variable size.
The reason that a TLP is not represented as a string of bytes consisting of header followed by data is due to the interface of the Intel FPGA PCIE Hard Core.

### Receiving TLPs

The PCIe library attempts to provide blocking semantics.
It does this by adding packets that are not a direct response to a DMA request to a queue, and returning them to the user only after the DMA call is complete.

```c
void next_tlp(struct RawTLP *out)
void next_completion_tlp(struct RawTLP *out)
```

These two functions are responsible for returning TLPs from the PCIe Hard Core to user code.
They allocate buffers for the TLPs from a statically defined pool of memory.
They do not guarantee that they return a valid TLP, as they may time out before one arrives.
**All** TLPs returned by these functions must have `free_raw_tlp_buffer` called on them before they go out of scope, even if they are not valid.

`next_tlp` returns the next TLP of any type.
If one is available in the queue, it will return that.
Otherwise it will poll the hard core 1000 times before returning.

`next_completion_tlp` returns the next TLP that is a completion.
It adds non-completion TLPs received over the course of the call to the queue to be returned by the next_tlp function, in order to allow the high-level DMA read functions to present a blocking interface.

```c
bool
is_raw_tlp_valid(struct RawTLP *tlp)
```

If either of the functions that returns a TLP does not receive a valid response, it indicates this by marking the RawTLP as invalid.
Currently this is encoded by setting the `header_length` field to -1, but it is recommended to use this function to check for this.

### Sending TLPs

```c 
int
send_tlp(struct RawTLP *tlp)
```

Sends the represented TLP.
In order to guarantee that it works properly, the header and data pointers must be qword aligned.
It is recommended that you allocate the tlp buffer using the `TLPQuadWord` datatype in order to ensure this.

### Creating Standard TLPs

```c
enum tlp_direction {
	TLPD_READ = 0, TLPD_WRITE = 1
};

enum tlp_completion_status {
	TLPCS_SUCCESSFUL_COMPLETION	        = 0,
	TLPCS_UNSUPPORTED_REQUEST		    = 1,
	TLPCS_CONFIGURATION_REQUEST_RETRY   = 2,
	TLPCS_RESERVED_LITERAL_3		    = 3,
	TLPCS_COMPLETER_ABORT			    = 4,
	TLPCS_RESERVED_LITERAL_5		    = 5,
	TLPCS_REQUEST_TIMEOUT			    = -1
};

enum tlp_at {
	TLP_AT_UNTRANSLATED,
	TLP_AT_TRANSLATION_REQUEST,
	TLP_AT_TRANSLATED,
	TLP_AT_RESERVED
};

void
create_completion_header(struct RawTLP *tlp,
	enum tlp_direction direction, uint16_t completer_id,
	enum tlp_completion_status completion_status, uint16_t bytecount,
	uint16_t requester_id, uint8_t tag, uint8_t loweraddress)

void
create_memory_request_header(struct RawTLP *tlp, enum tlp_direction direction,
	enum tlp_at at, uint16_t length, uint16_t requester_id, uint8_t tag,
	uint8_t lastbe, uint8_t firstbe, uint64_t address)

void
create_config_request_header(struct RawTLP *tlp, enum tlp_direction direction,
	uint16_t requester_id, uint8_t tag, uint8_t firstbe, uint16_t devfn,
	uint16_t address)
```

These three functions allow the creation of some standard TLP headers.
The definitions of the fields should be evident from the PCIe manual.
The RawTLP they take as input should have its header pointer initialised to an area of buffer large enough to contain the relevant header.

### Creating and Parsing Generic TLPs

If none of the above mechanisms serve your purpose, you can use the TLP positional structs.
These also form the mechanism for parsing TLPs.
The positional structs are named using a common pattern according to their purpose. 
Each name starts with with `TLP64`.
This is followed by a word referring to varieties of TLPs that the particular struct applies to, then `DWord`, and the 0-indexed position of that DWord within the header.
The fields of each DWord directly correspond to the field of the TLP in the PCIe manual.
For more information, see the defining file, `pcie.h`, or the PCIe manual.
The total list of structs is:

* `struct TLP64DWord0`. The very first DWord in a header, common to all TLPs.
* `struct TLP64RequestDWord1`. The second DWord, common to standard request TLPs.
* `struct TLP64MessageRequestDWord1`. For message requests.
* `struct TLP64CompletionDWord1`. The second DWord in a completion TLP.
* `struct TLP64CompletionDWord2` The third DWord in a completion TLP.
* `struct TLP64ConfigRequestDWord2`. The third DWord in a configuration-request TLP.

For positions in headers where the DWord has only one meaning &ndash; normally an address &ndash; no struct is used.
To make use of these structs, we recommend simply casting the pointers as appropriate.

### Endianness

BERI is big-endian, while the Intel platforms that host the attack device are little-endian, so attention has to be paid to endianness.
The `send_tlp` function handles the corrections that need to be made to the headers, but it is up to the user to do the same for the data.

In practice, we have found that to this the data must be parsed semantically into fields, and then each field must be endianness corrected.
An example of this can be found in the `endianness_swap_freebsd_mbuf_header` function in `attacks.c`.
This is aided as QEMU includes some functions for endianness correction in the file `qemu/bswap.h`.
It also includes a family of functions for converting functions specifically to and from the endianness of the 'CPU', which QEMU perceives to be the emulated CPU, but which is actually the CPU of the victim machine in our case.
These are defined with macros, and include, for example, `be32_to_cpu`, and `cpu_to_le64`, with `be` and `le` being valid endiannesses, and 16, 32, and 64 being valid sizes.

## Attack Platform Structure

The main function of the attack platform is in `test.c`, demonstrating that the platform grew organically.
It implements the minimal viable subset of the QEMU main loop that allows the model of the NIC to run.
It may not be perfect, as it was constructed at least partially with trial and error.
In order to allow the platform to respond to requests from the host, it makes use of QEMU's coroutine mechanism, which allows a function to yield control and be restarted from the same point.
It operates by repeatedly scheduling a `process_packet` coroutine to run, followed by a single iteration of the main loop.
The `process_packet` loop calls the `next_tlp` function until it stops returning valid TLPs, then yields control.
For each TLP received, the `process_packet` function calls `respond_to_packet`.
For memory and config writes, this finds the relevant structures representing the memory regions of the device models, and returns a response to a read, or writes the data as appropriate.

## NIC Model

The files that contain the implementation of the NIC model are in the `hw/net` directory, and are `e1000e.c`, `e1000e_core.h`, `e1000e_core.c` and `e1000_regs.h`.
By far the most useful is `e1000e_core.c`, which contains the parts of the code that actually perform the work, rather than presentation logic or definitions.
Most of the functions inside the file are reasonably descriptively named.
We have found that the `start_xmit` function that is called just before a transmit operation is simulated to be the most useful for carrying out many attacks, because it allows buffers to be modified just before they are cleaned by the host.
If you wish to interact with the function to carry out an attack, we recommend that you either use the `pre_transmit_hook` system, or add a new hook if that is unsuitable.
The counterpart to `start_xmit` is `start_recv`.

## Other Attack Tools

`snoop-mac.c`
-------------

MacOS does not do per-device mappings, so it is not necessary to emulate the detailed behaviour of a NIC in order to carry out an attack.
Correspondingly, `snoop-mac.c` is a standalone file that scans through MacOS memory in order to attempt to find vulnerable mbufs.
It does not work against the latest MacOS versions or attempt to actually carry out subversion of an mbuf, but may be illustrative as an example of how to write a program that interacts with PCIe without using the full NIC stack.

`ats-dummy.c`
-------------

Address Translation Services (ATS) are a suite of PCIe features that allow a peripheral to state that it has carried out the translation ordinarily performed by the IOMMU itself.
For more information, see either my thesis, or the PCIe spec.
Clearly, enabling ATS for an untrusted device constitutes a severe vulnerability.
This file is the minimum possible implementation of an Intel 82754L NIC that Linux will attach a driver for.
It is is modified to present the PCIe ATS capability.
Linux then enables ATS for the emulated device.

## Various Utilities

`crhexdump`
----------

This is a function that prints a reasonably aesthetic hexdump using printf and
putchar.



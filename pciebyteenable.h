static inline uint8_t first_byte_enable(uint64_t address, uint32_t length)
{
	uint8_t demuxed=0;
	uint32_t sat_length = 0;
	uint8_t firstbe = 0;

	// if the transaction is greater or equal to a DWord, fill first BE with ones
	sat_length = (length<4) ? length : 4;
	// BE bits can be either 0, 1, 3, 7 or 15
	demuxed = (1<<(sat_length)) - 1;
	// first BE depends on address as well as length
	// if len = 1, firstbe = 0001 << (address % 4)
	// if len = 2, firstbe = 0011 << (address % 4)
	// etc, all truncated to 4 bits
	firstbe = (demuxed << (address % 4)) & 0xF;

	// zero length is special
	// (we expect a length of 1024 words to be converted to
	// length field=0 downstream of this function)
	if (length == 0)
		firstbe = 0;

	return firstbe;
}

static inline uint8_t last_byte_enable(uint64_t address, uint32_t length)
{
	uint8_t end_phase=0;
	uint64_t end = 0;
	uint8_t lastbe = 0;

	// last BE only depends on (address+length) % 4
	// but twisted, so
	// aligned (a+l)%4=0 means 1<<3
	// 1 byte  (a+l)%4=1 means 1<<0
	// 2 bytes (a+l)%4=2 means 1<<1, etc
	end = (address + (uint64_t) length);
	end_phase = (uint8_t) ((end-1LL) % 4);
	lastbe = (1<<(end_phase+1)) - 1;
	if (length <= 4)
		lastbe = 0;
	
	return lastbe;
}

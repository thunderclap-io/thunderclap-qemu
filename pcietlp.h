uint32_t
create_memory_request(volatile TLPDoubleWord *tlp, uint32_t buffer_length,
	enum tlp_direction direction, uint16_t completer_id,
	uint16_t requester_id, uint8_t tag, uint8_t loweraddress,
	uint64_t memory_address, uint32_t memory_length);

int
parse_memory_response(volatile TLPDoubleWord *tlp, uint32_t tlp_length,
	uint32_t *response_buffer, uint32_t response_buffer_length,
	enum tlp_completion_status *completion_status,
	uint16_t *completer_id,
	uint16_t *requester_id, uint8_t *tag, uint32_t *returned_length);

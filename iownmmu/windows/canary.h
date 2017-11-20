int scan_memory_canary(uint64_t addr_start, uint64_t addr_end,
  uint64_t canary_word, int64_t canary_addr_delta,
  uint64_t payload);

int check_memory_canary(uint64_t addr_start, uint64_t addr_end,
  uint32_t canary_word, uint64_t canary_offset, int64_t canary_addr_delta,
  uint64_t payload);

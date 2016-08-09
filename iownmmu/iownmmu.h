uint64_t iovirtual_window_explorer(uint64_t window_start, uint64_t window_end, uint64_t (*process)(void *, uint64_t, uint64_t), uint64_t process_arg);

uint64_t kaslr_slide_symbol_process(void *mem, uint64_t unused, uint64_t symbol_static_address);

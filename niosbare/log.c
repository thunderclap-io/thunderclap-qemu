#include "log.h"
#include "baremetalsupport.h"

struct log_entry {
	int							string_id;
	enum log_item_format		format;
	uint64_t					data_item;
	bool						trailing_new_line;
};

static char **log_strings;
static struct log_entry log_entries[LOG_LENGTH];
static int next_log_record = 0;

void
set_strings(char *strings[])
{
	log_strings = strings;
}

void
log(int string_id, enum log_item_format format, uint64_t data_item,
	bool trailing_new_line)
{
	log_entries[next_log_record].string_id = string_id;
	log_entries[next_log_record].format = format;
	log_entries[next_log_record].data_item = data_item;
	log_entries[next_log_record].trailing_new_line = trailing_new_line;

	++next_log_record;

	if (next_log_record >= LOG_LENGTH) {
		print_log();
	}
}

void
print_log()
{
	for (int i = 0; i < next_log_record; ++i) {
		struct log_entry entry = log_entries[i];
		if (entry.string_id >= 0) {
			writeString(log_strings[entry.string_id]);
		}
		switch (entry.format) {
		case LIF_BOOL:
			if (entry.data_item) {
				writeString("true");
			} else {
				writeString("false");
			}
			break;
		case LIF_INT_32:
			write_int_32(entry.data_item, ' ');
			break;
		case LIF_UINT_32:
			write_uint_32(entry.data_item, ' ');
			break;
		case LIF_UINT_32_HEX:
			write_uint_32_hex(entry.data_item, '0');
			break;
		case LIF_INT_64:
			write_int_64(entry.data_item, ' ');
			break;
		case LIF_UINT_64:
			write_uint_64(entry.data_item, ' ');
			break;
		case LIF_UINT_64_HEX:
			write_uint_64_hex(entry.data_item, '0');
			break;
		}
		if (entry.trailing_new_line) {
			writeUARTChar('\r');
			writeUARTChar('\n');
		}
	}
	next_log_record = 0;
}

bool
last_data_for_string(int string_id, uint64_t *data)
{
	for (int i = (next_log_record - 1); i >= 0; --i) {
		struct log_entry entry = log_entries[i];
		if (entry.string_id == string_id) {
			*data = entry.data_item;
			return true;
		}
	}
	return false;
}

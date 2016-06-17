#ifndef LOG_H
#define LOG_H

#include <stdbool.h>
#include <stdint.h>

#define LOG_LENGTH 64

enum log_item_format {
	LIF_NONE,
	LIF_BOOL,
	LIF_INT_32,
	LIF_UINT_32,
	LIF_UINT_32_HEX,
	LIF_INT_64,
	LIF_UINT_64,
	LIF_UINT_64_HEX
};

/*
 * Sets up the array of strings.
 */
void set_strings(char *strings[]);

/*
 * Logs where strings to print are stored in a table.
 * When printing, the string will be printed, followed by the data item.
 * If the string_id is -1, only the data item will be printed.
 * If the log_item_format is none, the data item will not be printed.
 *
 * If the act of logging fills the log buffer, the entire log is printed and
 * cleared.
 */
void log(int string_id, enum log_item_format format, uint64_t data_item,
	bool trailing_new_line);

/*
 * Prints and clears the log.
 */
void print_log();

/*
 * Sets the uint64_t pointer to the most recently logged data_item for a given
 * string_id. Return bool on success, or false if no matching string id is
 * found.
 */
bool last_data_for_string(int string_id, uint64_t *data);

#endif

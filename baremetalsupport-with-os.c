/* I am aware this has a slightly contradictory name:
 * It's an implementation of the functions that would normally be achieved by
 * direct UART manipulation via the OS.
 */

#include "baremetalsupport.h"

void
writeUARTChar(char c)
{
	putchar(c);
}

void
writeString(char *s)
{
	printf("%s", s);
}

char readUARTChar()
{
	return (char)getchar();
}

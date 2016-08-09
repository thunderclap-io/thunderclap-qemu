#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include "iownmmu/BCM5701/mbuf.h"
#include "iownmmu/BCM5701/attack.h"
#include "sys/alt_timestamp.h"


int main() {
  printf("Hello from Nios II!\n");
  usleep(2*1000*1000);
  printf("Starting...\n");
  alt_timestamp_start();

  BCM5701_own(0, panic_14_5_0);

  return 0;
}

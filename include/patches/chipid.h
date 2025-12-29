#ifndef CHIPID_H
#define CHIPID_H

#include <stdint.h>

void chipid_patch(void);
extern uint8_t *get_chipid, *get_boardid;

#endif
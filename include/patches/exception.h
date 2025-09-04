#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <stdint.h>

void exception_patch(void);
extern uint32_t *sync_panic, *el1_eret;

#endif

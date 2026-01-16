// comm.h - Read/Write + Module Base
#ifndef _COMM_H
#define _COMM_H

#include <linux/types.h>

// IOCTL команды
#define OP_READ_MEM    0x801
#define OP_WRITE_MEM   0x802
#define OP_MODULE_BASE 0x803

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void* buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char* name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

#endif

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/types.h>
#include "memleak.h"

#define PRINT_FIELD(name) \
    printf("%-12s offset=%-3zu size=%-3zu\n", #name, offsetof(struct alloc_info, name), sizeof(((struct alloc_info *)0)->name))

int main(void) {
    printf("Struct event layout (total size = %zu bytes):\n", sizeof(struct alloc_info));
    printf("--------------------------------------------------\n");

    PRINT_FIELD(size);
    PRINT_FIELD(timestamp_ns);
    PRINT_FIELD(stack_id);

    return 0;
}
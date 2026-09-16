/*
 * dummy.c - a small vulnerable target for heapscope's demo.
 *
 * This exists so the library can be demonstrated without pointing it at
 * somebody's CTF challenge. The bug class is a common one:
 *
 *   - free() does not clear the slot pointer  -> use-after-free
 *   - edit() re-reads the size recorded at alloc time, which free() also never
 *     clears -> the stale size is used on a freed chunk
 *
 * That is enough to reach a tcache double free. glibc's tcache check compares
 * e->key against the tcache pointer, so clearing the key through the
 * use-after-free is enough to free the chunk a second time. On 2.34+ there is
 * also a walk of the bin, but that walk only runs when the key already matches,
 * so zeroing the key skips it too.
 *
 * Build:  make
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_SLOTS 2
#define MAX_SIZE  0x500

static char  *slots[MAX_SLOTS];
static size_t sizes[MAX_SLOTS];

static int read_long(const char *prompt, long *out)
{
    char buf[64];

    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, sizeof buf, stdin))
        return 0;
    *out = strtol(buf, NULL, 10);
    return 1;
}

static void do_alloc(void)
{
    long idx, size;

    if (!read_long("Index: ", &idx))
        exit(0);
    if (idx < 0 || idx >= MAX_SLOTS)
        return;
    if (!read_long("Size: ", &size))
        exit(0);
    if (size < 1 || size > MAX_SIZE)
        return;

    slots[idx] = malloc((size_t)size);
    if (!slots[idx])
        return;

    /* Recorded here, and never cleared on free. */
    sizes[idx] = (size_t)size;

    printf("Data: ");
    fflush(stdout);
    if (read(0, slots[idx], (size_t)size) < 0)
        exit(0);
}

static void do_free(void)
{
    long idx;

    if (!read_long("Index: ", &idx))
        exit(0);
    if (idx < 0 || idx >= MAX_SLOTS)
        return;

    /* The pointer stays in the slot, and the size stays recorded. */
    free(slots[idx]);
}

static void do_edit(void)
{
    long idx;

    if (!read_long("Index: ", &idx))
        exit(0);
    if (idx < 0 || idx >= MAX_SLOTS)
        return;

    printf("Data: ");
    fflush(stdout);

    /* Writes through the stale pointer using the stale size. */
    if (read(0, slots[idx], sizes[idx]) < 0)
        exit(0);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("heapscope demo target");
    puts("1. alloc  2. free  3. edit  4. quit");
    fflush(stdout);

    for (;;) {
        long choice;

        if (!read_long("Choice? ", &choice))
            break;

        switch (choice) {
        case 1: do_alloc(); break;
        case 2: do_free();  break;
        case 3: do_edit();  break;
        case 4: exit(0);
        default: break;
        }
    }
    return 0;
}

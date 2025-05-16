#include "arg_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARGS        64
#define MAX_POSITIONALS 64

typedef struct {
    char short_name;
    const char *long_name;
    arg_handler_t handler;
} arg_entry_t;

static arg_entry_t args[MAX_ARGS];
static int arg_count = 0;

static int g_argc;
static char **g_argv;

static char *positional_args[MAX_POSITIONALS + 1]; // +1 for NULL terminator
static int positional_count = 0;

char **init_args(int argc, char **argv) {
    g_argc           = argc;
    g_argv           = argv;
    positional_count = 0;

    // Pre-parse to collect positional arguments
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];

        if (arg[0] == '-') {
            if (arg[1] == '-') {
                i++; // skip value
            } else {
                i++; // skip value
            }
        } else {
            if (positional_count < MAX_POSITIONALS) {
                positional_args[positional_count++] = arg;
            }
        }
    }

    positional_args[positional_count] = NULL;
    return positional_args;
}

void add_arg(char one_letter, const char *string, arg_handler_t handler) {
    if (arg_count >= MAX_ARGS) {
        fprintf(stderr, "Too many arguments registered\n");
        exit(1);
    }

    args[arg_count].short_name = one_letter;
    args[arg_count].long_name  = string;
    args[arg_count].handler    = handler;
    arg_count++;
}

void parse_args(void) {
    for (int i = 1; i < g_argc; i++) {
        char *arg = g_argv[i];

        if (arg[0] == '-' && arg[1] != '-') {
            // Short form
            char key  = arg[1];
            char *val = (i + 1 < g_argc) ? g_argv[++i] : NULL;

            for (int j = 0; j < arg_count; j++) {
                if (args[j].short_name == key) {
                    args[j].handler(val);
                    goto next;
                }
            }

            fprintf(stderr, "Unknown short argument: -%c\n", key);
        } else if (strncmp(arg, "--", 2) == 0) {
            // Long form
            const char *key = arg + 2;
            char *val       = (i + 1 < g_argc) ? g_argv[++i] : NULL;

            for (int j = 0; j < arg_count; j++) {
                if (strcmp(args[j].long_name, key) == 0) {
                    args[j].handler(val);
                    goto next;
                }
            }

            fprintf(stderr, "Unknown long argument: --%s\n", key);
        }

    next:
        continue;
    }
}

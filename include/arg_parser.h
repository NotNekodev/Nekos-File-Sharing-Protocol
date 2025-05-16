#ifndef ARG_PARSER_H
#define ARG_PARSER_H

typedef void (*arg_handler_t)(char *value);

char **init_args(int argc, char **argv);
void add_arg(char one_letter, const char *string, arg_handler_t handler);
void parse_args(void);

#endif

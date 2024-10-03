#ifndef PARSER_OPTION_H
#define PARSER_OPTION_H
void parsers_option(int argc, char *argv[]);
void print_help();
void scan_wifi(int scan_option);
extern int log_level_set; // khai bao bien toan cuc de dung o cac file khac

#endif // PARSER_OPTION_H


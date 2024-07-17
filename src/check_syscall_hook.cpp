#include <cstdio>
#include <cstring>
#include "color.h"

const int LINE_LEN = 256;
const int N_SYSCALL = 1024;

char syscall_table[N_SYSCALL][LINE_LEN];

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        puts("Invalid argument!");
    }

    FILE *tbl_file = fopen(argv[1], "r");

    if (tbl_file == nullptr) {
        puts(YEL "Cannot open syscall table file." RESET);

        return 1;
    }

    char line[LINE_LEN];

    while (!feof(tbl_file))
    {
        fgets(line, LINE_LEN, tbl_file);

        for (int i = 0; line[i] && i < LINE_LEN; ++i)
        {
            if (line[i] == '#')
            {
                line[i] = '\0';
                break;
            }
        }

        int syscall_number;
        char abi[LINE_LEN], syscall_name[LINE_LEN];
        int cnt = sscanf(line, "%d%s%s", &syscall_number, abi, syscall_name);

        if (cnt == 3)
        {
            // printf("%d %s\n", syscall_number, syscall_name);

            strncpy(syscall_table[syscall_number], syscall_name, LINE_LEN);
        }
    }

    FILE *vol3_output = fopen(argv[2], "r");

    if (vol3_output == nullptr) {
        puts(YEL "Cannot open output file of Volatilty 3." RESET);

        return 1;
    }

    for (int i = 0; i < 4; ++i)
        fgets(line, LINE_LEN, vol3_output);

    bool is_table_info_printed = false;
    bool is_syscall_hook_detected = false;

    while (!feof(vol3_output))
    {
        fgets(line, LINE_LEN, vol3_output);

        int syscall_number;
        char table_address[LINE_LEN], table_name[LINE_LEN], handler_address[LINE_LEN], symbol[LINE_LEN];
        int cnt = sscanf(line, "%s%s%d%s%s", table_address, table_name, &syscall_number, handler_address, symbol);

        if (cnt == 5 && !is_table_info_printed)
        {
            is_table_info_printed = true;

            printf("Syscall Table Found. Table Address: %s, Table Name: %s\n", table_address, table_name);
        }

        if (!strcmp(symbol, "UNKNOWN"))
        {
            if (!is_syscall_hook_detected)
            {
                is_syscall_hook_detected = true;

                puts(RED "Syscall Table Hooking detected." RESET);
                puts("Syscall Number | Handler Address | Syscall Name");
            }
            printf(YEL "%14d %17s %14s\n" RESET, syscall_number, handler_address, syscall_table[syscall_number]);
        }
    }

    if (!is_syscall_hook_detected)
    {
        puts(GRN "No Syscall Table Hooking detected.");
    }
}
#include <cstdio>
#include <cstring>
#include "color.h"

const int LINE_LEN = 256;

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        puts("Invalid argument!");
    }

    FILE *vol3_output = fopen(argv[1], "r");

    if (vol3_output == nullptr)
    {
        puts(YEL "Cannot open output file of Volatilty 3." RESET);

        return 1;
    }

    char line[LINE_LEN];

    for (int i = 0; i < 4; ++i)
        fgets(line, LINE_LEN, vol3_output);

    bool is_inline_hook_detected = false;

    puts("                                                                                   ");

    while (!feof(vol3_output))
    {
        fgets(line, LINE_LEN, vol3_output);

        int prefix_len;
        char func_type[LINE_LEN], func_name[LINE_LEN], func_addr[LINE_LEN], hook_type[LINE_LEN], target_addr[LINE_LEN], instr_offset[LINE_LEN];
        int cnt = sscanf(line, "%s%s%s%s%s%s%n", func_type, func_name, func_addr, hook_type, target_addr, instr_offset, &prefix_len);

        for (int i = prefix_len; line[i]; ++i)
        {
            if (line[i] == '\n')
            {
                line[i] = '\0';
            }
        }

        if (cnt == 6 && func_addr[0] == '0' && func_addr[1] == 'x')
        {
            if (!is_inline_hook_detected)
            {
                is_inline_hook_detected = true;

                puts(RED "Kernel inline Hooking detected." RESET);
                puts("Function Type |           Function Name | Function Address | Hook Type | Target Address | Instruction Offset | Note");
            }
            printf(YEL "%13s%26s%19s%12s%17s%21s   %s\n" RESET, func_type, func_name, func_addr, hook_type, target_addr, instr_offset, line + prefix_len);
        }
    }

    if (!is_inline_hook_detected)
    {
        puts(GRN "No inline Hooking detected." RESET);
    }
}
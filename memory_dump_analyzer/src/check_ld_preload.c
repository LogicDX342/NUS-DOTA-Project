#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "color.h"
#include <stdbool.h>

int main()
{
    bool is_preload_file = false;
    bool is_preload_env = false;

    if (access("/etc/ld.so.preload", F_OK) == 0)
    {
        is_preload_file = true;
        puts(RED "/etc/ld.so.preload found!" RESET);
        if (access("/etc/ld.so.preload", R_OK) == 0)
        {

            FILE *f = fopen("/etc/ld.so.preload", "r");

            if (f == NULL)
            {
                printf(YEL "Error when reading file." RESET);
            }
            else
            {
                puts("The file content is:");

                for (char c = fgetc(f); c != EOF; c = fgetc(f))
                    putchar(c);
            }
        }
    }

    const char *env = getenv("LD_PRELOAD");
    if (env != NULL)
    {
        is_preload_env = true;
        puts(RED "LD_PRELOAD enironment variable found!" RESET);

        printf(YEL "The vairable is: %s\n" RESET, env);
    }

    if (!is_preload_file && !is_preload_env)
    {
        puts(GRN "No LD_PRELOAD library found." RESET);
    }
    return 0;
}
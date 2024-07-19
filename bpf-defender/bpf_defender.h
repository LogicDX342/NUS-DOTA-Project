#ifndef __BPF_DEFENDER_H
#define __BPF_DEFENDER_H

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127

#define TYPE_BPF 0
#define TYPE_INSMOD 1

struct event {
	int pid;
	int ppid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
    bool waiting_for_password;
	int type;
    bool authroized;
};

#endif /* __BPF_DEFENDER_H */
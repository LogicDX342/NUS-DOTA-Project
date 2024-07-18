#include "bpf_defender.skel.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
// #include <sys/resource.h>
#include <signal.h>
#include <termios.h>
#include "bpf_defender.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

char *get_exe_path(pid_t pid)
{
	char link_path[256];
	char *exe_path = (char *)malloc(1024); // Allocate memory for the path
	if (!exe_path) {
		fprintf(stderr, "Memory allocation failed\n");
		return NULL;
	}

	// Construct the path to the symbolic link
	snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);

	// Read the symbolic link
	ssize_t len = readlink(link_path, exe_path, 1024 - 1);
	if (len == -1) {
		perror("readlink");
		free(exe_path);
		return NULL;
	}

	exe_path[len] = '\0'; // Null-terminate the result
	return exe_path;
}

#define MAX_LINE_LENGTH 1024
char **get_strings(const char *file_path, int *count)
{
	char *prefixes[] = { "tp/",
			     "tracepoint/",
			     "fentry/",
			     "kprobe/",
			     "ksyscall/",
			     "uprobe/",
			     "usdt/"
			     "kprobe.multi/"
			     "lsm/"
			     "raw_tracepoint/"
			     "iter/" };
	int num_prefixes = sizeof(prefixes) / sizeof(prefixes[0]);

	char command[256];
	snprintf(command, sizeof(command), "strings %s", file_path);
	FILE *fp = popen(command, "r");
	if (!fp) {
		perror("Failed to run command");
		exit(1);
	}
	char **fs_strings = NULL;
	char line[MAX_LINE_LENGTH];
	*count = 0;

	while (fgets(line, MAX_LINE_LENGTH, fp) != NULL) {
		for (int i = 0; i < num_prefixes; i++) {
			if (strstr(line, prefixes[i]) == line) {
				fs_strings = realloc(fs_strings, (*count + 1) * sizeof(char *));
				if (!fs_strings) {
					perror("Memory allocation failed");
					exit(1);
				}
				fs_strings[*count] = strdup(line);
				if (!fs_strings[*count]) {
					perror("Memory allocation failed");
					exit(1);
				}
				(*count)++;
				break;
			}
		}
	}

	pclose(fp);
	return fs_strings;
}

static char *get_pwd()
{
	struct termios old, new;
	char *pwd = (char *)malloc(64);
	if (!pwd) {
		fprintf(stderr, "Memory allocation failed\n");
		return NULL;
	}

	if (tcgetattr(fileno(stdin), &old) != 0) {
		perror("tcgetattr");
		free(pwd);
		return NULL;
	}
	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(stdin), TCSAFLUSH, &new) != 0) {
		perror("tcsetattr");
		free(pwd);
		return NULL;
	}

	scanf("%64s", pwd);

	(void)tcsetattr(fileno(stdin), TCSAFLUSH, &old);
	printf("\n");
	return pwd;
}

int input_map_fd;
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	if (!e->waiting_for_password) {
		if (e->authroized) {
			printf(ANSI_COLOR_GREEN "BPF program is authorized\n" ANSI_COLOR_RESET);
			printf("\n" ANSI_COLOR_GREEN
			       "BPF program installation successful.\n" ANSI_COLOR_RESET);
			kill(e->pid, 18);
		} else {
			printf(ANSI_COLOR_RED "BPF program is not authorized\n" ANSI_COLOR_RESET);
			kill(e->pid, 9);
		}
		return 0;
	}

	printf("\n" ANSI_COLOR_CYAN "A BPF program is trying to install:\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW
	       "--------------------------------------------------\n" ANSI_COLOR_RESET);
	printf(ANSI_COLOR_YELLOW "%-16s %-7s %-7s %s\n" ANSI_COLOR_RESET, "COMM", "PID", "PPID",
	       "FILENAME");
	printf("%-16s %-7d %-7d %s\n\n", e->comm, e->pid, e->ppid, e->filename);

	char *exe_path = get_exe_path(e->pid);
	if (!exe_path) {
		fprintf(stderr, ANSI_COLOR_RED "Failed to get executable path\n" ANSI_COLOR_RESET);
		return 1;
	}

	int count;
	char **fs_strings = get_strings(exe_path, &count);
	if (!fs_strings) {
		fprintf(stderr, ANSI_COLOR_RED
			"Cannot find BPF hooks in the executable\n" ANSI_COLOR_RESET);
		free(exe_path);
	}
	printf("Found %d BPF hooks in the executable:\n", count);
	for (int i = 0; i < count; i++) {
		printf(ANSI_COLOR_GREEN " - %s\n" ANSI_COLOR_RESET,
		       fs_strings[i]); // Add a dash for list items
		free(fs_strings[i]);
	}
	printf(ANSI_COLOR_YELLOW
	       "--------------------------------------------------\n" ANSI_COLOR_RESET);

	free(fs_strings);
	free(exe_path);

	char user_input[10];
	printf("\n" ANSI_COLOR_MAGENTA "Do you want to continue? (y/n): " ANSI_COLOR_RESET);
	do {
		scanf("%9s", user_input);
		if (strcmp(user_input, "n") == 0) {
			printf(ANSI_COLOR_RED
			       "User denied the installation of BPF program\n" ANSI_COLOR_RESET);
			kill(e->pid, 9);
			return 0;
		} else if (strcmp(user_input, "y") == 0) {
			break;
		} else {
			printf(ANSI_COLOR_YELLOW
			       "Invalid input, please enter y or n: " ANSI_COLOR_RESET);
		}
	} while (1);

	printf("\nEnter password to continue: ");
	char *pwd = get_pwd();

	int key = 0;
	if (bpf_map_update_elem(input_map_fd, &key, pwd, BPF_ANY) != 0) {
		fprintf(stderr, ANSI_COLOR_RED "Failed to update input map\n" ANSI_COLOR_RESET);
		return 1;
	}
	kill(0, 0);
	return 0;
}

int main()
{
	struct bpf_defender_bpf *skel;
	struct ring_buffer *rb = NULL;
	int rb_fd, err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open and load BPF application */
	skel = bpf_defender_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	printf("\033[H\033[J");

	/* Set up BPF program */
	printf("Set the password: ");
	char *pwd = get_pwd();
	strncpy(skel->data->pwd, pwd, sizeof(skel->data->pwd));
	skel->bss->my_pid = getpid();
	free(pwd);
	printf(ANSI_COLOR_GREEN "BPF program is running ...\n" ANSI_COLOR_RESET);

	/* Attach BPF program */
	err = bpf_defender_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Find the ring buffer map FD */
	rb_fd = bpf_map__fd(skel->maps.my_ringbuf);
	if (rb_fd < 0) {
		fprintf(stderr, "Failed to find ring buffer map FD\n");
		goto cleanup;
	}

	/* Set up ring buffer */
	rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Find the input map FD */
	input_map_fd = bpf_map__fd(skel->maps.input_map);
	if (input_map_fd < 0) {
		fprintf(stderr, "Failed to find input map FD\n");
		goto cleanup;
	}

	/* Poll the ring buffer */
	while (1) {
		ring_buffer__poll(rb, -1); /* -1 means wait indefinitely */
	}

cleanup:
	ring_buffer__free(rb);
	bpf_defender_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
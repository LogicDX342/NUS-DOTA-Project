.PHONY: clean

CC := gcc
CXX := g++

all:
	$(CC) -static check_ld_preload.c -o ../build/check_ld_preload
	$(CXX) check_syscall_hook.cpp -o ../build/check_syscall_hook

clean:
	rm -rf ../build

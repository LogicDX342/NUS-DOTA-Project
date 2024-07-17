#!/bin/bash

SUDO=''
if [ `id -u` -ne 0 ]; then
    SUDO='sudo'
fi

echo "Detecting LD_PRELOAD rootkits..."
$SUDO ./build/check_ld_preload

echo ""

echo "Detecting sys_call_table hooks..."
$SUDO insmod ./build/lime.ko "path=/tmp/lime.lime format=lime"
$SUDO rmmod lime

if [ ! -d "tmp" ]; then
	mkdir tmp
fi
python3 ./volatility3/vol.py -f /tmp/lime.lime linux.check_syscall.Check_syscall > tmp/syscall_result.txt

build/check_syscall_hook resource/syscall_64.tbl tmp/syscall_result.txt

rm -rf tmp



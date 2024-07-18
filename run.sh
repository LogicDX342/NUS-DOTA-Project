#!/bin/bash

RED="\e[31m"
GRN="\e[32m"
NC="\e[0m"

SUDO=''
if [ `id -u` -ne 0 ]; then
    SUDO='sudo'
fi

echo "Detecting LD_PRELOAD rootkits..."
$SUDO ./build/check_ld_preload

echo "--------------------------------"


echo "Dumping memory..."
$SUDO insmod ./build/lime.ko "path=/tmp/lime.lime format=lime"

if [ $? -ne 0 ]; then
    echo "${RED}Cannot use LiME to dump memory!${NC}"
    exit
fi

$SUDO rmmod lime

echo ""

echo "Detecting sys_call_table hooks..."

if [ ! -d "tmp" ]; then
	mkdir tmp
fi

python3 ./volatility3/vol.py -f /tmp/lime.lime linux.check_syscall.Check_syscall > tmp/syscall_result.txt

build/check_syscall_hook resource/syscall_$(getconf LONG_BIT).tbl tmp/syscall_result.txt

echo "--------------------------------"

echo "Detecting kernel inline hooks..."

cp ./src/vol3_plugin/check_inline_hook.py ./volatility3/volatility3/plugins/linux/

python3 ./volatility3/vol.py -f /tmp/lime.lime linux.check_inline_hook.Check_inline_hook > tmp/inline_result.txt

build/check_inline_hook tmp/inline_result.txt

rm -f ./volatility3/volatility3/plugins/linux/check_inline_hook.py

# rm -rf tmp



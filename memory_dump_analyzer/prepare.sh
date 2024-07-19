#!/bin/bash

SUDO=''
if [ `id -u` -ne 0 ]; then
    SUDO='sudo'
fi

cd src
make clean
mkdir ../build
make all

cd ../volatility3
pip3 install -r requirements.txt
mkdir volatility3/symbols/linux

cd ../
$SUDO chmod +x ./resource/dwarf2json
$SUDO ./resource/dwarf2json linux --elf "/usr/lib/debug/boot/vmlinux-$(uname -r)" --system-map "/boot/System.map-$(uname -r)" > "volatility3/volatility3/symbols/linux/$(uname -r).json"

cd LiME/src
make clean
make

cp lime-$(uname -r).ko ../../build/lime.ko

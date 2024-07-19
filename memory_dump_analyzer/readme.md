# Rootkit Detection Tools

## Usage

(Make sure you have enough disk space: your RAM size + the dbgsym kernl image size.) 

```bash
git clone --recursive https://github.com/LogicDX342/NUS-DOTA-Project.git
```

For `Ubuntu`:
Follow [this guide](https://ubuntu.com/server/docs/debug-symbol-packages#getting-dbgsymddeb-packages) to get the dbgsym version of your current kernel, such as `sudo apt install linux-image-$(uname -r)-dbgsym`.

Run `prepare.sh` to build the symbol tables.

Then run `run.sh`.

## Credit
- `resource/syscall_64.tbl` from [linux](https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl)
- `resource/dwarf2json` from [dwaef2json](https://github.com/volatilityfoundation/dwarf2json/releases/tag/v0.8.0)
- [volatiltiy3](https://github.com/volatilityfoundation/volatility3)
- [Linux Memory Extractor](https://github.com/504ensicsLabs/LiME)

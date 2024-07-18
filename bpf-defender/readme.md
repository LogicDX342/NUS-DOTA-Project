# Using eBPF to detect and defense rootkit

## Install Dependencies

You will need `clang` (at least v11 or later), `libelf` and `zlib` to build
the defender and detector, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

To get started, enter the "Detector_Defender" directory.

```shell
$ cd Detector_Defender
```
## Rootkit Detector

In the "Detector and Defender" directory, run the command:
```shell
$ make bpf_dectector
```

You need root privilege to run the detector:
```shell
$ sudo ./bpf_dectector
```

You need to go through the output. If for some system call, there's a warning that the address is NOT in the ``.text`` segment, there is a high chance that you are attacked by some rootkit, or other malicious programs that hook your syscall table.

## Rootkit Defender

In the "Detector and Defender" directory, run the command:
```shell
$ make bpf_defender
```

You need root privilege to run the detector:
```shell
$ sudo ./bpf_defender
```

Set and use a secondary password, to determine whether a eBPF installation will be discarded or not. 
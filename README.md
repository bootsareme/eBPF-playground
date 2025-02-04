# eBPF-playground
Simple eBPF programs for learning

## Environment
Programs are targeted for the Linux kernel and compiled and ran with `bcc`. Install `bcc` using `apt`:
```sh
sudo apt-get install bpfcc-tools linux-headers-generic
```

## Running Programs
Source files can be loaded and ran with `sudo python3 loader.py *.c`.

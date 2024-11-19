from collections import defaultdict
from pwn import ELF
import re


sym_pattern = r"^[a-zA-Z0-9]{8}$"
sym_pattern = re.compile(sym_pattern)

sym_jmp_idx_pattern = r"^[a-zA-Z0-9]{8}.\d+$"
sym_jmp_idx_pattern = re.compile(sym_jmp_idx_pattern)

elf = ELF("./topology")
symbols = elf.symbols


cnt = 0
_cnt = 0
base_addr = 0x400000
symbol_and_jmp_idx = defaultdict(lambda: [None, None])
for symname, addr in symbols.items():
    if sym_pattern.match(symname):
        cnt += 1
        # print(f"{symname}: {addr:x}")

        symbol_and_jmp_idx[symname][0] = addr + base_addr

    elif sym_jmp_idx_pattern.match(symname):
        _cnt += 1
        symbol_and_jmp_idx[symname[:8]][1] = addr + base_addr
        # print(f"{symname}: {addr:x}")

assert cnt == 99 and _cnt == 99

# print(symbol_and_jmp_idx)
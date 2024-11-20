from collections import defaultdict
from pwn import ELF
from elf_utils import XELF
import re


sym_pattern = r"^[a-zA-Z0-9]{8}$"
sym_pattern = re.compile(sym_pattern)

sym_jmp_idx_pattern = r"^[a-zA-Z0-9]{8}.\d+$"
sym_jmp_idx_pattern = re.compile(sym_jmp_idx_pattern)

elf_path = "./topology"
elf = ELF(elf_path)
xelf = XELF(elf_path)
symbols = elf.symbols


cnt = 0
_cnt = 0
base_addr = 0x400000
func_cnt = 99
# 0: address
# 1: addrof jump index
# 2: end (set later)
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

assert cnt == func_cnt and _cnt == func_cnt

# get all `ret` in functions with capstone
# analyze functions (start and end)
l = sorted(list(symbol_and_jmp_idx.items()), key=lambda x: x[1][0])
for i in range(func_cnt - 1):
    current_f = l[i]
    next_f = l[i+1]

    symbol_and_jmp_idx[current_f[0]].append(next_f[1][0])  # 半開区間

# from binary ninja
symbol_and_jmp_idx["fzJ7JTkt"].append(0xe5792 + base_addr)

ret_addrs = []
for symname, (addr, _, end) in symbol_and_jmp_idx.items():
    g_insns = xelf.disasm(addr - base_addr, end - base_addr)
    for insn in g_insns:
        mnemonic = insn.mnemonic

        if mnemonic == "ret":
            # print(insn)
            ret_addrs.append(insn.address + base_addr)


if __name__ == "__main__":
    print(symbol_and_jmp_idx)
    print(ret_addrs)
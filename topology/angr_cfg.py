# ref: https://docs.angr.io/en/latest/analyses/cfg.html


import angr
import sys
from elf_utils import XELF

# maybe useless
CFGEMU = "-e" in sys.argv or "--emulated" in sys.argv


filename = "./topology_stripped"
elf = XELF(filename)

angr_base_addr = 0x400000

# extract function pointers from binary (`f` global variable)
function_count = 99
byte_len = 8 * function_count
raw_func_ptrs = elf.get_bytes_from_address(0xea020, byte_len)
func_ptrs = []
for i in range(0, byte_len, 8):
    func_ptrs.append(int.from_bytes(raw_func_ptrs[i:i+8], "little") + angr_base_addr)


proj = angr.Project(filename, auto_load_libs=False)

print(f"[+] CFG type: {'CFGEmulated' if CFGEMU else 'CFGFast'}")

cfg = proj.analyses.CFGEmulated() if CFGEMU else proj.analyses.CFGFast(normalize=True)  # normalizeオプションを有効にすると偽陽性が各関数で1つ減るっぽい

functions = cfg.kb.functions
print(len(functions))

funcdata = []

ret_addrs = set()
for func_addr in func_ptrs:
    func = functions[func_addr]
    ret_sites = func.ret_sites
    for ret_site in ret_sites:
        bytes_str = ret_site.bytestr
        if bytes_str[-1] != 0xc3:
            continue

        ret_addr = ret_site.addr + len(bytes_str) - 1
        ret_addrs.add(ret_addr)
    # print(dir(func))
    jmp_idx_xref = next(func.xrefs)
    jmp_idx_addr= jmp_idx_xref.dst

    # print(func.name, hex(jmp_idx_addr))
    funcdata.append((func_addr, jmp_idx_addr))

    # break

ret_addrs = list(ret_addrs)
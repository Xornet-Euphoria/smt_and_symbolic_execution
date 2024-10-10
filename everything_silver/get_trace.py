import regex, pickle
from pwn import disasm
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

poketext_match = regex.compile(r"ptrace\(PTRACE_POKETEXT, (\d+), (0x[0-9a-f]+), (0x[0-9a-f]+)\)")

md = Cs(CS_ARCH_X86, CS_MODE_64)

with open("./log.txt") as f:
    lines = f.readlines()

ops = []

for l in lines:
    l = l.strip()
    if l.startswith("--- SIGCHLD"):
        continue

    if "PTRACE_CONT" in l:
        continue

    if l.endswith(" = 0"):
        l = l.replace(" = 0", "")

    if res := poketext_match.match(l):
        rip = int(res[2], 16)
        value = int(res[3], 16)

        if value != 0xcccccccccccccccc:
            code = int.to_bytes(value, 8, "little")
            code = code.replace(b"\xcc", b"")
            ops.append((rip, code))
            # print(f"[+] {rip:x}:")
            op = next(md.disasm(code, rip))
            print(f"0x{op.address:x}: {op.mnemonic} {op.op_str}")
            # print(disasm(code, vma=rip, arch="amd64"))

with open("./ops.pkl", "wb") as f:
    pickle.dump(ops, f)
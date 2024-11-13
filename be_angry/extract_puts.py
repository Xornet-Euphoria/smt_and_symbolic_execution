from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn, CS_OP_IMM, x86_const
from elftools.elf.elffile import ELFFile

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
tracked_rdi = 0

def is_direct_call(op: CsInsn):
    if op.mnemonic != "call":
        return False

    operand = op.operands[0]
    return operand.type == CS_OP_IMM


# check lea rdi, [rip + ???]
# and calculate src: rip + ???
def check_rdi(op: CsInsn):
    global tracked_rdi
    mnemonic = op.mnemonic
    operands = op.operands

    if mnemonic == "lea" and len(operands) == 2:
        first = operands[0]
        second = operands[1]

        if first.type == x86_const.X86_OP_REG and first.reg == x86_const.X86_REG_RDI:

            if second.type == x86_const.X86_OP_MEM:
                mem = second.mem
                base_reg = mem.base

                if base_reg == x86_const.X86_REG_RIP:
                    rip = op.address + len(op.bytes)
                    target = rip + mem.disp

                    dump_op(op)
                    print(f"[+] target: 0x{target:x}")
                    tracked_rdi = target



def dump_op(op: CsInsn):
    print(f"0x{op.address:x} {op.mnemonic} {op.op_str}")


f = open("./chall", "rb")
elf = ELFFile(f)
text = elf.get_section_by_name(".text").data()

puts_addr = 0x401070


avoids = []
base_addr = 0x400000
for op in md.disasm(text, base_addr + 0x10a0):
    mnemonic = op.mnemonic

    check_rdi(op)

    if is_direct_call(op):
        called_addr = op.operands[0].imm

        if called_addr == puts_addr:
            print(f"[+] found: `puts(0x{tracked_rdi:x})`")
            if tracked_rdi == 0x403004:
                avoids.append(op.address + base_addr)

f.close()

print(avoids)
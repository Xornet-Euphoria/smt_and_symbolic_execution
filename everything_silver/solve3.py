import triton
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from triton import MemoryAccess, Instruction, CPUSIZE

md = Cs(CS_ARCH_X86, CS_MODE_64)
ctx = triton.TritonContext(triton.ARCH.X86_64)
ast = ctx.getAstContext()

constraints = []

# init
# 0. set a rip
ctx.setConcreteRegisterValue(ctx.registers.rip, 0x7fc52560a100)

# 1. set a concrete value to rdi (maybe stack region)
rdi = 0x555500000000
buf_start_addr = rdi
buf_end_addr = rdi+0x28
ctx.setConcreteRegisterValue(ctx.registers.rdi, rdi)
ctx.setConcreteMemoryValue(MemoryAccess(buf_start_addr+40, CPUSIZE.BYTE), 0)

# 2. symbolize memory (rdi+0x28 - rdi+0x28+40) and set ASCII-printable constraints
for i in range(40):
    var_name = f"c_{i}"
    ctx.symbolizeMemory(MemoryAccess(buf_start_addr+i, CPUSIZE.BYTE), var_name)
    constraints.append(ast.variable(ctx.getSymbolicVariable(var_name)) >= 0x20)
    constraints.append(ast.variable(ctx.getSymbolicVariable(var_name)) <= 0x7e)

# start execution
import pickle
with open("./ops.pkl", "rb") as f:
    ops = pickle.load(f)


for addr, b in ops:
    op = next(md.disasm(b, addr))
    print(f"0x{op.address:x}: {op.mnemonic} {op.op_str}")

    if op.address == 0x7fc52560a11d:
        break
    if op.mnemonic in ["cmp", "jne"]:
        continue

    inst = Instruction()
    inst.setAddress(addr)
    inst.setOpcode(b)

    ctx.processing(inst)
    # print(inst)

# compare loop (with manual modification of operations)
eax_mul = 0xdeadbeef
xs = [
    0x66993576,
    0x3bd23991,
    0x6000c8f0,
    0x06f05a64,
    0x74843975,
    0xc77bd448,
    0xef9ba544,
    0x6244ed09,
    0x83124ea1,
    0x4da78b03,
]
for x in xs:
    # mov    eax, DWORD PTR [rdi]
    inst = Instruction()
    inst.setAddress(0x7fc52560a11d)
    inst.setOpcode(b"\x8b\x07")

    ctx.processing(inst)

    # imul   eax, eax, 0xdeadbeef + 0xc0ffee * i
    inst = Instruction()
    inst.setAddress(0x7fc52560a11f)
    b = b"\x69\xc0" + eax_mul.to_bytes(4, "little")
    eax_mul += 0xc0ffee
    inst.setOpcode(b)

    ctx.processing(inst)
    # add    rdi, 0x4
    inst = Instruction()
    inst.setAddress(0x7fc52560a125)
    inst.setOpcode(b"\x48\x83\xc7\x04")

    ctx.processing(inst)

    eax = ctx.getSymbolicRegister(ctx.registers.rax).getAst()
    constraints.append(eax == x)

m = ctx.getModel(ast.land(constraints))

flag = ""
for k, v in sorted(m.items()):
    flag += chr(v.getValue())

print(flag)
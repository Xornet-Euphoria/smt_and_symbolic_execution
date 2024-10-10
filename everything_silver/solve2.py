# solver with the wrapper of z3.Concat and z3.Extract

from typing import Any
import z3


# todo:
# - apply model
# - intager assignment
# - using solver
class AddrSpace(object):
    # default address space is stack region
    def __init__(self, baseaddr=0x555500000000, use_rva=False) -> None:
        self.memory = {}
        self.bvs = {}
        self.baseaddr = baseaddr
        self.use_rva = use_rva

        if baseaddr & 0x1000 != 0:
            print(f"[WARN] base address is not aligned: {baseaddr:x}")


    def get_rva(self, i):
        return self.baseaddr + i
    

    def get_addr(self, addr):
        return self.get_rva(addr) if self.use_rva else addr


    def set_symbol(self, size, start: int | None=None):
        if start is None:
            start = self.baseaddr
        elif self.use_rva:
            start = self.baseaddr + start

        for i in range(size):
            addr = start+i
            bv = z3.BitVec(f"byte_{addr}", 8)

            self.memory[addr] = bv
            self.bvs[addr] = bv


    def get_byte(self, addr: int):
        addr = self.get_addr(addr)

        return self.memory[addr]
    

    def set_byte(self, addr, bv):
        self.memory[self.get_addr(addr)] = bv


    def set_imm_byte(self, addr, x):
        self.memory[self.get_addr(addr)] = x


    def get_word(self, addr):
        addr = self.get_addr(addr)
        ret = z3.Concat(self.memory[addr+1], self.memory[addr])
        
        return ret
    

    def set_word(self, addr, bv: z3.BitVecRef):
        if bv.size() != 16:
            raise ValueError("the bit length of `bv` must be 16")
        
        addr = self.get_addr(addr)
        
        for i in range(2):
            l = 8 * i
            h = l+7
            self.memory[addr+i] = z3.Extract(h, l, bv)


    def get_dword(self, addr):
        addr = self.get_addr(addr)
        ret = z3.Concat(self.memory[addr+3], self.memory[addr+2], self.memory[addr+1], self.memory[addr])

        return ret
    

    def set_dword(self, addr, bv: z3.BitVecRef):
        if bv.size() != 32:
            raise ValueError("the bit length of `bv` must be 32")
        
        addr = self.get_addr(addr)
        
        for i in range(4):
            l = 8 * i
            h = l+7
            self.memory[addr+i] = z3.Extract(h, l, bv)


mem = AddrSpace(use_rva=True)
mem.set_symbol(41)
base = mem.baseaddr

solver = z3.Solver()

for i in range(0, 40):
    solver.add(mem.get_byte(i) < 0x7f)
    solver.add(mem.get_byte(i) > 0x1f)

solver.add(mem.get_byte(40) == 0)
mem.set_imm_byte(40, 0)

# mul_x = 0x47
# for i in range(40):
#     j = i + 1
#     x = z3.Extract(i*8+7, i*8, flag)
#     al = z3.Extract(j*8+7, j*8, flag)
    
#     al = al * mul_x
#     x ^= al
#     x += 0x35
#     inp.append(x)

#     mul_x += 3

mul_x = 0x47
for i in range(40):
    # x = z3.Extract(i*8+7, i*8, flag)
    x = mem.get_byte(i)
    # al = z3.Extract(j*8+7, j*8, flag)
    al = mem.get_byte(i+1)
    
    al = al * mul_x
    x ^= al
    x += 0x35
    mem.set_byte(i, x)

    mul_x += 3


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

mul_eax = 0xdeadbeef

for i in range(0, 40, 4):
    cmp = xs[i//4]
    # x = z3.Concat(inp[i+3], inp[i+2], inp[i+1], inp[i])
    x = mem.get_dword(i)
    x *= mul_eax

    mul_eax += 0xc0ffee

    solver.add(cmp == x)

res = solver.check()
if res != z3.sat:
    print("ha?")
    exit()

# sat path
m = solver.model()

flag = ""
for addr, bv in mem.bvs.items():
    b = m[bv].as_long()
    flag += chr(b)

print(flag)
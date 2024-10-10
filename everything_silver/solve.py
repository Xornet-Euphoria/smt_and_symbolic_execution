import z3


solver = z3.Solver()

inp = []
flag = z3.BitVec(f"flag", 41*8)

for i in range(0, 40):
    solver.add(z3.Extract(i*8+7, i*8, flag) < 0x7f)
    solver.add(z3.Extract(i*8+7, i*8, flag) > 0x1f)

solver.add(z3.Extract(327, 320, flag) == 0)

mul_x = 0x47
for i in range(40):
    j = i + 1
    x = z3.Extract(i*8+7, i*8, flag)
    al = z3.Extract(j*8+7, j*8, flag)
    
    al = al * mul_x
    x ^= al
    x += 0x35
    inp.append(x)

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
    x = z3.Concat(inp[i+3], inp[i+2], inp[i+1], inp[i])
    x *= mul_eax

    mul_eax += 0xc0ffee

    solver.add(cmp == x)

print(solver.check())
m = solver.model()

_flag = m[flag].as_long()
print(int.to_bytes(_flag, 41, "big")[::-1])
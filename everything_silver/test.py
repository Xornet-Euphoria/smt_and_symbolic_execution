known = b"Alpaca"
m = 256

buf = bytearray([0] * 40)
view = memoryview(buf)

mul_x = 0x47
for i in range(len(known) - 1):
    x = known[i]
    al = known[i+1]
    
    al = (al * mul_x) % m
    x ^= al
    x += 0x35
    x %= m

    buf[i] = x
    mul_x += 3

print(view[:4].cast("@I")[0])
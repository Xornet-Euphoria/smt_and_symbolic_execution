import angr, claripy
from collections import defaultdict
from anal_elf import symbol_and_jmp_idx
from tqdm import tqdm

import pickle
import os
pkl_filename = "candidates.pkl"

if os.path.exists(pkl_filename):
    print("[+] using cache")
    with open(pkl_filename, "rb") as f:
        candidates = pickle.load(f)

        flag = ""
        for i in range(10):
            d = candidates[i]
            current_s = None
            current_i = 0
            for s, i in d.items():
                if i > current_i:
                    current_i = i
                    current_s = s

            flag += current_s

        print(flag)

    exit()
else:
    print("[+] Let's angrrrrrrrrrrrrr")

# from binary ninja
func_addrs = [
    0x0000000000002349, 0x0000000000004879,
    0x000000000000720f, 0x0000000000009b93,
    0x000000000000b7f1, 0x000000000000d230,
    0x000000000000ff1d, 0x0000000000012253,
    0x0000000000014591, 0x0000000000016d79,
    0x000000000001949d, 0x000000000001b7de,
    0x000000000001dd99, 0x000000000001fbf2,
    0x00000000000220e1, 0x0000000000023d0b,
    0x0000000000025892, 0x0000000000027757,
    0x000000000002a192, 0x000000000002cb4f,
    0x000000000002e879, 0x000000000003169c,
    0x000000000003339f, 0x0000000000035445,
    0x00000000000377db, 0x0000000000039b9a,
    0x000000000003c0ce, 0x000000000003ed75,
    0x00000000000420aa, 0x00000000000447bf,
    0x000000000004688d, 0x0000000000048b2d,
    0x000000000004a98d, 0x000000000004c883,
    0x000000000004f645, 0x0000000000051abc,
    0x0000000000054610, 0x00000000000570d6,
    0x0000000000059372, 0x000000000005bd94,
    0x000000000005e571, 0x00000000000607b1,
    0x0000000000061c13, 0x0000000000063cc4,
    0x00000000000666b4, 0x0000000000068cee,
    0x000000000006b326, 0x000000000006d526,
    0x000000000006fc3c, 0x00000000000721f9,
    0x0000000000073f7e, 0x0000000000076b82,
    0x00000000000792a8, 0x000000000007c1a6,
    0x000000000007e7e0, 0x000000000008058d,
    0x00000000000826e7, 0x000000000008474b,
    0x00000000000872db, 0x000000000008a16e,
    0x000000000008c37f, 0x000000000008e5a9,
    0x00000000000913c6, 0x0000000000093198,
    0x0000000000095978, 0x0000000000097827,
    0x000000000009a2b6, 0x000000000009c8b5,
    0x000000000009ef2d, 0x00000000000a118b,
    0x00000000000a366b, 0x00000000000a5c37,
    0x00000000000a7dbc, 0x00000000000aa152,
    0x00000000000ac1f9, 0x00000000000ae63d,
    0x00000000000afbaf, 0x00000000000b25ef,
    0x00000000000b4741, 0x00000000000b7083,
    0x00000000000b8a9c, 0x00000000000bb3dc,
    0x00000000000bdeab, 0x00000000000c105c,
    0x00000000000c3472, 0x00000000000c563f,
    0x00000000000c7c0b, 0x00000000000c9d84,
    0x00000000000ccd4a, 0x00000000000cf04e,
    0x00000000000d0374, 0x00000000000d22f4,
    0x00000000000d44ad, 0x00000000000d700d,
    0x00000000000da451, 0x00000000000dc40b,
    0x00000000000deee4, 0x00000000000e13fa,
    0x00000000000e37ae
]
# lifting
func_addrs = [0x400000 + addr for addr in func_addrs]

buf_addr = 0x1000


# not working FXXK
def ret_br(st):
    print("test")
    # st.solver.add(st.regs.rax == 0)
    # res = st.solver.eval(st.mem[buf_addr])
    
    # print(res)
    
    # st.globals["halt_exploration"] = True


rounds = 10
candidates = [defaultdict(int) for i in range(rounds)]

proj = angr.Project("./topology", auto_load_libs=False)

for symname, (addr, jmp_idx_addr) in tqdm(symbol_and_jmp_idx.items()):
    for jmp_idx in range(rounds):
        state = proj.factory.blank_state(
            addr=addr,
            add_options={
                "ZERO_FILL_UNCONSTRAINED_MEMORY",
                "ZERO_FILL_UNCONSTRAINED_REGISTERS"
            }
        )
        
        bv = claripy.BVS("inp", 64)
        state.memory.store(buf_addr, bv)
        state.regs.rdi = buf_addr
        state.memory.store(jmp_idx_addr, jmp_idx.to_bytes(4, "little"))

        # why not working ???
        # state.inspect.b("return", when=angr.BP_BEFORE, action=ret_br)

        simgr = proj.factory.simulation_manager(state)
        res = None

        while sts := simgr.active:
            st = sts[0]
            if st.solver.eval(st.addr) == 0:
                regs = st.regs
                st.solver.add(st.regs.rax == 0)
                res = st.solver.eval(bv, cast_to=bytes).decode(errors="ignore")
                break

            simgr.step()

        # print(f"[{addr:x}-{jmp_idx:x}] {res}")
        candidates[jmp_idx][res] += 1

# save
with open(pkl_filename, "wb") as f:
    pickle.dump(candidates, f)

flag = ""
for i in range(10):
    d = candidates[i]
    current_s = None
    current_i = 0
    for s, i in d.items():
        if i > current_i:
            current_i = i
            current_s = s

    flag += current_s

print(flag)
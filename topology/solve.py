from collections import defaultdict


rounds = 10

def recover_flag(result: list[defaultdict]):
    flag = ""
    for i in range(rounds):
        d = result[i]
        current_s = ""
        current_i = 0
        for s, i in d.items():
            if i > current_i:
                current_i = i
                current_s = s

        flag += current_s

    return flag

import pickle
import os
pkl_filename = "candidates.pkl"

if os.path.exists(pkl_filename):
    print("[+] using cache")
    with open(pkl_filename, "rb") as f:
        candidates = pickle.load(f)

        print(recover_flag(candidates))

    exit()
else:
    print("[+] Let's angrrrrrrrrrrrrr")

buf_addr = 0x1000


from anal_elf import symbol_and_jmp_idx
from tqdm import tqdm
import angr, claripy


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

print(recover_flag(candidates))
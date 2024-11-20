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
import sys

# execution forced even if candidates are cached
FORCE = "-f" in sys.argv

pkl_filename = "candidates.pkl"

if not FORCE and os.path.exists(pkl_filename):
    print("[+] using cache")
    with open(pkl_filename, "rb") as f:
        candidates = pickle.load(f)

        print(recover_flag(candidates))

    exit()
else:
    print("[+] Let's angrrrrrrrrrrrrr")

buf_addr = 0x1000


from anal_elf import symbol_and_jmp_idx, ret_addrs
from tqdm import tqdm
import angr, claripy

candidates = [defaultdict(int) for i in range(rounds)]


def ret_hook(st):
    # print("[DEBIG] RET HOOK HIT", st)
    st.solver.add(st.regs.rax == 0)
    res = st.solver.eval(st.memory.load(buf_addr, 8), cast_to=bytes).decode(errors="ignore")
    
    candidates[globals_for_hook["jmp_idx"]][res] += 1

    st.globals["halt_exploration"] = True


proj = angr.Project("./topology", auto_load_libs=False)
globals_for_hook = {
    "jmp_idx": 0
}

for addr in ret_addrs:
    proj.hook(addr, ret_hook)


for symname, (addr, jmp_idx_addr, _) in tqdm(symbol_and_jmp_idx.items()):
    for jmp_idx in range(rounds):
        globals_for_hook["jmp_idx"] = jmp_idx
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

        # state.inspect.b("instruction", when=angr.BP_BEFORE, action=ret_br)

        simgr = proj.factory.simulation_manager(state)
        simgr.run()


# save
with open(pkl_filename, "wb") as f:
    pickle.dump(candidates, f)

print(recover_flag(candidates))
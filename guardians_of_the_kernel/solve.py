import angr, claripy
from Crypto.Util.number import long_to_bytes

module_path = "./fs/flag_checker.ko"
proj = angr.Project(module_path, auto_load_libs=False)

# 方針
# 1. ioctlコードをconcreteに渡すx3
# 2. _copy_from_userにパッチ (buffer変数をシンボリック変数にする)
# 3. printkをhookですっ飛ばす
# 4. layers変数は全部非ゼロにしておく (段階を経てチェックする仕組みになっている)
# 5. 各layerのクリアアドレスに到達することを条件にぶち込む

angr_base_addr = 0x400000  # default?
ioctl_addr = angr_base_addr + 0x10
kbuf = angr_base_addr + 0x8a0
kbuf_size = 0x100
layers = angr_base_addr + 0x500

code_ctx = {
    0x7000: (angr_base_addr + 0x77, 6),
    0x7001: (angr_base_addr + 0x161, 7),
    0x7002: (angr_base_addr + 0x1cd, 12),
}

class printk_hook(angr.SimProcedure):
    def run(self, fmt, *args):
        print("[+] hooked (printk)")
        print(self.state.regs.rdi)


class copy_from_user_hook(angr.SimProcedure):
    def run(self, kbuf, ubuf, size):
        return 0

        size = size.concrete_value
        bv = claripy.BVS("ubuf", size)
        print("2")
        # why it isnt execute?
        self.state.memory.store(kbuf.concrete_value, bv)

proj.hook_symbol("printk", printk_hook())
proj.hook_symbol("_copy_from_user", copy_from_user_hook())


flag = b""

for code, ctx in code_ctx.items():
    print(f"[+] current code: 0x{code:x}")
    state = proj.factory.blank_state(
        addr=ioctl_addr,
        add_options={
            "ZERO_FILL_UNCONSTRAINED_MEMORY",
            "ZERO_FILL_UNCONSTRAINED_REGISTERS"
        }
    )
    target_addr = ctx[0]
    # init: set hooks, layers (var), code
    state.regs.esi = code
    ubuf = claripy.BVS(f"inp-{code:x}", kbuf_size)
    print(ubuf)
    state.memory.store(kbuf, ubuf)
    # layers (var)
    state.memory.store(layers, b"\xff" * 12)

    simgr = proj.factory.simulation_manager(state)
    # remnant of debugging (for me in the future)
    # while simgr.active and simgr.active[0].regs.rip.concrete_value != 0:
    #     print(simgr.active)
    #     print(simgr.active[0].regs.rip.concrete_value)
    #     print(simgr.active[0].block().capstone)
    #     simgr.step()

    simgr.explore(find=target_addr)

    if simgr.found:
        state = simgr.found[0]
        v = state.solver.eval(ubuf)
        partial_flag =  long_to_bytes(v).replace(b"\x00", b"")

        flag += partial_flag

print(flag)

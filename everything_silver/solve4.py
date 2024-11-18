import angr
import claripy
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

md = Cs(CS_ARCH_X86, CS_MODE_64)

# ==========================================================================
# shellcodeの整形
import pickle
with open("./ops.pkl", "rb") as f:
    ops = pickle.load(f)


start_addr = 0
shellcode = b""
for addr, b in ops:
    addr = addr & 0xfff
    op = next(md.disasm(b, addr))
    # print(f"0x{op.address:x}: {op.mnemonic} {op.op_str}")

    if op.address & 0xfff == 0x11d:
        break
    if op.mnemonic in ["cmp", "jne"]:
        continue

    shellcode += b

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

base_addr = 0
current_addr = len(shellcode)
hook_addrs = []
for x in xs:
    # mov    eax, DWORD PTR [rdi]
    shellcode += b"\x8b\x07"

    # imul   eax, eax, 0xdeadbeef + 0xc0ffee * i
    b = b"\x69\xc0" + eax_mul.to_bytes(4, "little")
    shellcode += b
    eax_mul += 0xc0ffee

    # imul eax, eax, ??? を実行後にフックするためのアドレスを取得
    current_addr = len(shellcode)
    hook_addrs.append(base_addr + current_addr)

    # add    rdi, 0x4
    shellcode += b"\x48\x83\xc7\x04"

# check
for op in md.disasm(shellcode, 0):
    print(f"0x{op.address:x}: {op.mnemonic} {op.op_str}")


def add_constraint(x):
    def solver_hook(st):
        eax = st.regs.eax
        st.solver.add(eax == x)

    return solver_hook

# ==========================================================================
# https://docs.angr.io/en/stable/api.html#angr.load_shellcode
proj = angr.load_shellcode(shellcode, arch="amd64")

for addr, x in zip(hook_addrs, xs):
    proj.hook(addr, add_constraint(x))


# 初期状態の作成 with おまじない
state = proj.factory.blank_state(
    addr=base_addr,
    add_options={
        "ZERO_FILL_UNCONSTRAINED_MEMORY",
        "ZERO_FILL_UNCONSTRAINED_REGISTERS"
    }
)

# シンボリック変数を作成
input_size = 0x28  # 40バイトの入力
sym_input = claripy.BVS('sym_input', input_size * 8)
buf_addr = 0x10000
state.memory.store(buf_addr, sym_input)  # バッファアドレスに格納
state.memory.store(buf_addr + 40, 0)     # null-terminated
state.regs.rdi = buf_addr

# シミュレーションマネージャーの作成
simgr = proj.factory.simulation_manager(state)

# 探索条件（終了アドレス到達）
target_addr = len(shellcode)  # シェルコード終了後のアドレス
simgr.explore(find=target_addr)

# 結果の確認
if simgr.found:
    found_state = simgr.found[0]
    regs = found_state.regs

    # 多分要らん
    # for i in range(input_size):
    #     b = sym_input.get_byte(i)
    #     found_state.solver.add(b < 0x7f)
    solution = found_state.solver.eval(sym_input, cast_to=bytes)
    print("Found solution:", solution)
else:
    print("No solution found.")
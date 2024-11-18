import angr, claripy


def set_str_to_rdi(st, addr):
    regs = st.regs
    rdi = regs.rdi
    if st.solver.symbolic(rdi):
        return False
    
    # .concrete_value or .cv
    return regs.rdi.cv == addr


proj = angr.Project("./chall", auto_load_libs=False)
inp = claripy.BVS("inp", 8 * 0x19)

s = proj.factory.entry_state(
    # args=[proj.filename],
    stdin=inp,
    add_options={
        "ZERO_FILL_UNCONSTRAINED_MEMORY",
        "ZERO_FILL_UNCONSTRAINED_REGISTERS"
    }
)

simgr = proj.factory.simulation_manager(s)

# puts(rdi) でrdiが "Incorrect!!" を指しているものをavoid
#                   "Correct!!"   を指しているものをfind
# todo: call命令を条件に指定する (まだrdiしか見てないのでほとんどあり得ないが偽陽性がある)
# -> stateは基本ブロック単位なので結構厄介 (call putsを含むブロックのstateにヒットした時、まだlea rdi, &incorrectもcall putsも呼ばれていない)
# -> よってこのようなcallをstateから検知するのはガチガチに厳密には出来なさそう
# -> find_f, avoid_fはputsのPLTに飛んだ時を見ている
# 多分breakpointを上手く使ったほうが良いので気が向いたら実装する
incorrect_s =  0x403004
correct_s = 0x403010

# I hate using posix.dumps(fd)
find_f = lambda st: set_str_to_rdi(st, correct_s)
avoid_f = lambda st: set_str_to_rdi(st, incorrect_s)

# correct_addr = 0x402539
simgr.explore(find=find_f, avoid=avoid_f)

if simgr.found:
    found_s = simgr.found[0]
    print(found_s.solver.eval(inp, cast_to=bytes))
else:
    print("ha?")
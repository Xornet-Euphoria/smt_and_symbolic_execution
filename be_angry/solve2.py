import angr, claripy


puts_addr = 0x401070
incorrect_s = 0x403004
correct_s = 0x403010


def call_br(st):
    func_addr = st.solver.eval(st.inspect.function_address)

    if func_addr != puts_addr:
        return
    rdi = st.regs.rdi

    if st.solver.eval(rdi) == incorrect_s:
        st.globals["halt_exploration"] = True
        return
    elif st.solver.eval(rdi) == correct_s:
        print(st.solver.eval(inp, cast_to=bytes))
        simgr.move(from_stash="active", to_stash="found")


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

# puts(rdi) でrdiが "Incorrect!!" を指しているものをavoid
#                   "Correct!!"   を指しているものをfind
s.inspect.b("call", when=angr.BP_BEFORE, action=call_br)

simgr = proj.factory.simulation_manager(s)
simgr.explore()

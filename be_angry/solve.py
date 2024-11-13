import angr, claripy


proj = angr.Project("./chall")
inp = claripy.BVS("inp", 8 * 0x19)

s = proj.factory.entry_state(
    args=[proj.filename],
    stdin=inp,
    add_options={
        "ZERO_FILL_UNCONSTRAINED_MEMORY",
        "ZERO_FILL_UNCONSTRAINED_REGISTERS"
    }
)

simgr = proj.factory.simulation_manager(s)
simgr.explore(find=0x402539)

print(simgr.run())

if simgr.found:
    found_s = simgr.found[0]
    print(found_s.solver.eval(inp, cast_to=bytes))
else:
    print("ha?")
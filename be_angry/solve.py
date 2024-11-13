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

avoids = [8393592, 8393781, 8393809, 8393939, 8395051, 8395079, 8395107, 8395294, 8395322, 8395579, 8396272, 8396300, 8396328, 8396468, 8396664, 8396793, 8396821, 8396849, 8398109, 8398137, 8398165, 8398193, 8398221, 8398419, 8398532]

simgr = proj.factory.simulation_manager(s)
simgr.explore(find=0x402539, avoid=avoids)

print(simgr.run())

if simgr.found:
    found_s = simgr.found[0]
    print(found_s.solver.eval(inp, cast_to=bytes))
else:
    print("ha?")
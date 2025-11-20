import angr, claripy
import sys


USE_VERI = "--veritesting" in sys.argv

if __name__ == "__main__":
    if USE_VERI:
        print("[!] if the target binary is for veritesting, this script uses tooooooo manyyyyyyy memory and causes a hang.")
        print("so if you understand this risk or implement safe solution (with veritesting), please type 'VERITESTING'")
        check = input("> ")
        if check != "VERITESTING":
            print("[+] BYE!")
            exit()
        else:
            print("[+] LET'S GOOOOOO")
    target = "./target" if USE_VERI else "./target_no_veri"
    proj = angr.Project(target, auto_load_libs=False)
    inp = claripy.BVS("inp", 8 * 0x20)
    s = proj.factory.entry_state(
        stdin=inp,
        add_options={
            "ZERO_FILL_UNCONSTRAINED_MEMORY",
            "ZERO_FILL_UNCONSTRAINED_REGISTERS"
        }
    )

    simgr = proj.factory.simulation_manager(s, veritesting=USE_VERI)

    while simgr.active and simgr.active[0].regs.rip.concrete_value != 0:
        print(simgr.active)
        if len(simgr.active) > 16:
            print("[!] so many states!!!")
            print("    please implement safer solution")
            break
        for st in simgr.active:
            if b"OK" in st.posix.dumps(1):
                print("[+] Found!")
                print(st.solver.eval(inp, cast_to=bytes))
                exit()
        simgr.step()

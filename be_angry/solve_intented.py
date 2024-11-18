#!/usr/bin/env python3
import angr
import logging

logging.getLogger("angr").setLevel("CRITICAL")
angr.manager.l.setLevel("CRITICAL")
proj = angr.Project("./chall", auto_load_libs=False)

simgr = proj.factory.simgr()
# simgr.explore(find=lambda s: b"Correct" in s.posix.dumps(1))
target = 0x402539
avoids = [8393592, 8393781, 8393809, 8393939, 8395051, 8395079, 8395107, 8395294, 8395322, 8395579, 8396272, 8396300, 8396328, 8396468, 8396664, 8396793, 8396821, 8396849, 8398109, 8398165, 8398193, 8398221, 8398419, 8398532]
simgr.explore(find=target, avoid=avoids)
if len(simgr.found) > 0:
    found = simgr.found[0].posix.dumps(0).decode("utf-8", "ignore")
    print(found)
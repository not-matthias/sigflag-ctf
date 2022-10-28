 
import angr

p = angr.Project("level3")
good = 0x01012a1 + 0x400000
bad = 0x001012a + 0x400000

sm = p.factory.simulation_manager()
print(sm.explore(find=good, avoid=bad))

for f in sm.found:
    print(f.posix.dumps(0))
    print(f.posix.dumps(1))
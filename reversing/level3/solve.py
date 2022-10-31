import angr

p = angr.Project("level3")
good = 0x01012A1 + 0x400000
bad = 0x001012A + 0x400000

sm = p.factory.simulation_manager()
print(sm.explore(find=good, avoid=bad))

for f in sm.found:
    print(f.posix.dumps(0))
    print(f.posix.dumps(1))


# import angr
# import claripy
# from string import printable


# good = 0x0128e
# bad =  0x012a1

# p = angr.Project("level3")

# # Create user input
# USER_DATA_LEN = 0x20
# user_data = claripy.BVS("user_data", USER_DATA_LEN*8)

# s = p.factory.entry_state(stdin=user_data)

# # Add constraint (only allow ascii characters)
# for i in range(USER_DATA_LEN):
#     s.solver.add(
#         claripy.Or(*(
#             user_data.get_byte(i) == x
#             for x in printable
#         ))
#     )

# sm = p.factory.simulation_manager(s)
# sm.run()

# for pp in sm.deadended:
#     input = pp.posix.dumps(0)
#     out = pp.posix.dumps(1)
#     print(input)
#     print(out)

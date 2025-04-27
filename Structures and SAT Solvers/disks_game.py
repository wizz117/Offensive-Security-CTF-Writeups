goal = 2147483647

def recurse(arg1, arg2, arg3, arg4):
    global total_moves
    if arg1:
        recurse(arg1 - 1, arg2, arg4, arg3)
        recurse(arg1 - 1, arg4, arg3, arg2)
        total_moves += 1

for arg1 in range(1, 50):
    total_moves = 0
    recurse(arg1, 0x53, 0x54, 0x41)
    print(f"No of disks: {arg1}, Total Moves: {total_moves}")
    if total_moves == goal:
        print(f"The number of disks is: {arg1}")
        break


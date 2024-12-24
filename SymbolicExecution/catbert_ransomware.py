# This script uses the angr symbolic execution framework to solve a binary challenge
# The challenge involves finding a key that satisfies certain conditions in a binary
# The key must be made up of printable ASCII characters

import angr      # Framework for symbolic execution of binaries
import claripy   # Constraint solver used by angr
import logging 
import argparse  # For parsing command line arguments
import sys       # For accessing command line arguments and exit functionality

# Parse command line arguments
parser = argparse.ArgumentParser(description='Solve binary challenge with angr')
parser.add_argument('input_file', help='Path to the input file to process')
args = parser.parse_args()

# Uncomment to enable debug logging if needed
#logging.getLogger('angr').setLevel(logging.DEBUG)

# Read and parse the challenge file structure
# The file format appears to be:
# - 8 bytes: header
# - 4 bytes: offset (little endian)
# - 4 bytes: size (little endian)
# - [offset] bytes: skip to data section
# - [size] bytes: actual data to process
try:
    with open(args.input_file, 'rb') as f:
        f.read(8)                                    # Skip header
        offset = int.from_bytes(f.read(4), 'little') # Get offset to data
        size = int.from_bytes(f.read(4), 'little')   # Get size of data
        f.seek(offset, 0)                            # Jump to data section
        data = list(f.read(size))                    # Read data into list for modification
except FileNotFoundError:
    print(f"Error: Input file '{args.input_file}' not found")
    sys.exit(1)
except Exception as e:
    print(f"Error reading input file: {e}")
    sys.exit(1)

# Create 16 symbolic variables for the key
# Each variable is 8 bits (1 byte) wide
# These will be solved for by the symbolic execution
key = [claripy.BVS(f'k{i}', 8) for i in range(16)]

# Insert the symbolic key bytes into specific positions in the data
# The pattern suggests pairs of bytes being replaced:
# - Positions 5,4 get key[0],key[1]
# - Positions 12,11 get key[2],key[3]
# And so on...
data[5] = key[0]
data[4] = key[1]
data[12] = key[2]
data[11] = key[3]
data[19] = key[4]
data[18] = key[5]
data[26] = key[6]
data[25] = key[7]
data[33] = key[8]
data[32] = key[9]
data[40] = key[10]
data[39] = key[11]
data[47] = key[12]
data[46] = key[13]
data[54] = key[14]
data[53] = key[15]

# Define important addresses in the target binary
RET_ADDR = 0x43191e        # Return address we're looking for
STATUS_ADDR = 0x568ed0     # Address where status is stored
FUN_ENTRY_ADDR = 0x431285  # Entry point of the function we're analyzing
DATA_PTR_ADDR = 0x4e85a8   # Address where pointer to our data will be stored

# Load the target binary and create initial state
proj = angr.Project('0.efi')
base_addr = proj.loader.min_addr 
print(hex(base_addr))  # Print base address for debugging
state = proj.factory.call_state(FUN_ENTRY_ADDR)

# Add constraints to ensure all key bytes are printable ASCII characters
# Printable range is from 32 (space) to 126 (tilde)
for k in key:
    state.solver.add(k >= 32)  # Must be at least space character
    state.solver.add(k <= 126) # Must be at most tilde character

# Allocate memory for our data and write it to the state
data_sec = state.heap.allocate(size)
for i in range(size):
    state.mem[data_sec + i].uint8_t = data[i]

# Store pointer to our data at the expected address
state.mem[DATA_PTR_ADDR].uint64_t = data_sec

# Create simulation manager to explore possible paths
simgr = proj.factory.simulation_manager(state)

# Define success condition function
def found(state):
    if state.addr == RET_ADDR:        # If we've reached the return address
        status = state.memory.load(STATUS_ADDR, 8)  # Load status value
        state.add_constraints(status != 0)          # Status must be non-zero
        return state.solver.satisfiable()           # Check if constraints can be satisfied

# Explore the binary until we find a solution
# - find: Look for states that satisfy our found() function
# - avoid: Don't explore past the return address otherwise
simgr.explore(find=found, avoid=RET_ADDR)

# Verify we found exactly one solution
assert len(simgr.found) == 1
state = simgr.found[0]

# Extract and print the solution
# Convert each key byte to its concrete value and combine into bytes object
print(bytes((state.solver.eval(k) for k in key)))

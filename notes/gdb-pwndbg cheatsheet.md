gdb / pwndbg notes 

***
gdb
***

### Running & Controlling Execution

|     |     |     |
| --- | --- | --- |
| **Command** | **Shortcut** | **What It Does** |
| `run [args]` | `r` | Starts execution of the program with optional command-line arguments. |
| `continue` | `c` | Resumes program execution until the next breakpoint or crash. |
| `stepi` | `si` | Executes exactly **one assembly instruction** (steps _into_ function calls). |
| `nexti` | `ni` | Executes exactly **one assembly instruction** (steps _over_ function calls). |
| `kill` | `k` | Terminates the current execution of the running process inside GDB. |

<br>

### Setting Breakpoints

|     |     |     |
| --- | --- | --- |
| **Command** | **What It Does** | **Example** |
| `break <location>` | Sets a breakpoint at a function name or memory address. | `b main`<br><br>`b *0x08048436` |
| `info breakpoints` | Lists all active breakpoints with their IDs. | `i b` |
| `delete <id>` | Removes a specific breakpoint by its number. | `d 1` |

<br>

### Inspecting Registers

Registers store the current state of execution (e.g., `EIP`, `ESP`, `EBP`).

- `info registers` (or `i r`): Displays values held in all general-purpose registers.
- `info registers eip esp ebp`: Displays values for specific registers only.
- `print $eip` (or `p $eip`): Prints the current value stored inside a specific register in decimal or hex.

<br>

### Examining Memory (`x` Command)

The `x` (examine) command is GDB's most powerful tool for inspecting memory. Its syntax follows this structure:
$$\\text{x/}\[N\]\[F\]\[U\]\\text{\<address>\}$$

- **$N$ (Count):** Number of memory units to display (e.g., `10`).
- **$F$ (Format):** `x` (Hex), `s` (String), `i` (Instruction/Disassembly), `c` (Char).
- **$U$ (Unit Size):** `b` (Byte), `h` (Halfword - 2 bytes), `w` (Word - 4 bytes), `g` (Giant - 8 bytes).

<br>

### Examples:

```
# Examine 4 words (16 bytes total) in Hex at the top of the stack (ESP)
x/4wx $esp

# Examine 20 bytes as an ASCII string starting at a specific memory address
x/s 0x0804a000

# Examine 10 disassembly instructions starting at the entry point / main
x/10i $eip

# Examine 16 bytes in Hex format relative to EBP
x/16bx $ebp-0x10

```

<br>

### Disassembling Code

- `disassemble main` (or `disas main`): Shows the assembly instructions for a specific function.
- `disassemble $eip, +20`: Disassembles 20 bytes starting from the current instruction pointer.

***
pwndbg adds in additional features
***
+ **start**: Start the program and stop at the first convenient location (like main).
+ **entry**: Start the program and stop at the absolute entry point.
+ **nearpc**: Display disassembled instructions near the current program counter.
+ **context**: Show the current register values, stack, and disassembly view
+ **telescope**: Deeply inspect memory addresses with automatic pointer dereferencing and type tracking.
+ **vmmap**: Print virtual memory regions and permission mapping (similar to /proc/pid/maps).
+ **hexdump**: View memory contents in a clean hex format.search: Search memory for specific patterns, values, or strings.


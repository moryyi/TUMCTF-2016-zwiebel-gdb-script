"""
- Open within gdb shell, using command:
    source filename.py

- Make sure that the ptrace in __printf has been patched.
- Put anything in the input.txt to run this program.

- The flag is:
    hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}

- This gdb python script is inspired by liveoverflow's radare2 script.
"""


import gdb
import re
import sys


class GdbSolver:
    def __init__(self):
        self.gdb = gdb
        self.disasm = []
        self.disasm_index = -1

        self.flag = [0 for _ in range(100)]
        self.pre_flag = ""
        return

    def start(self):
        self.gdb.execute("set disassembly-flavor intel")
        breakpoints = self.gdb.breakpoints()
        if len(breakpoints) == 0:
            self.gdb.Breakpoint("*0x00400875")

        self.gdb.execute("r < input.txt")
        self.step_in()
        return

    def step_over(self):
        self.gdb.execute("ni")
        return

    def step_in(self):
        self.gdb.execute("si")
        return

    def extract_cur_opcode(self):
        cur_opcode = self.gdb.execute("x/i $pc", to_string=True)
        cur_opcode = cur_opcode[
            cur_opcode.index(">") + 1:
        ]
        # cur_opcode[0]: address of current instruction
        # cur_opcode[1]: actual instruction
        cur_opcode = cur_opcode.split(":")
        cur_opcode = [x.strip() for x in cur_opcode]
        cur_opcode[0] = int(cur_opcode[0], 0x10)

        cur_opcode[1] = re.split(r" |,", cur_opcode[1])
        cur_opcode[1] = list(filter(None, cur_opcode[1]))
        return cur_opcode

    def detect_jmp_opcode(self):
        while True:
            self.step_over()
            # Delete all breakpoints.
            # This is used because large amounts of breakpoints
            #   will be set to skip the `loop` opcode.
            # It is okay not to clear these breakpoints.
            self.gdb.execute("delete breakpoints")

            cur_opcode = self.extract_cur_opcode()
            self.disasm.append(cur_opcode)
            self.disasm_index += 1
            if cur_opcode[1][0] in ["je", "jne"]:
                break
            elif cur_opcode[1][0] == "loop":
                # Set a breakpoint right after this instruction
                #   and continue to skip the long loop process.
                self.gdb.Breakpoint(f"*{cur_opcode[0] + 0x2}")
                self.gdb.execute("c")
            elif cur_opcode[1][0] == "syscall":
                # If all conditions are handled correctly,
                #   syscall will be executed at very last.
                self.display_flag()
                break
            else:
                # Any other common opcodes
                pass
        return cur_opcode[1][0]

    def solve(self):
        while True:
            if self.detect_jmp_opcode() == "syscall":
                break
            offset = int(self.disasm[self.disasm_index - 2][1][-1][5:-1], 0x10)
            value = int(self.disasm[self.disasm_index - 1][1][-1], 0x10)
            jmp_opcode = self.disasm[self.disasm_index][1][0]
            if jmp_opcode == "je" or jmp_opcode == "jz":
                value = value
                self.flag[offset] = self.flag[offset] | value
                self.clear_zf()
            elif jmp_opcode == "jne" or jmp_opcode == "jnz":
                # `& 0b01111111` is used because of the fact
                #   that ASCII code only contains 7 valid bits.
                value = (value ^ 0xFF) & 0b01111111
                self.flag[offset] = self.flag[offset] & value
                self.toggle_zf()
            else:
                break
            self.display_flag()
        return

    def toggle_zf(self):
        self.gdb.execute("set $ZF = 6 ")
        self.gdb.execute("set $eflags |= (1 << $ZF)")
        return

    def clear_zf(self):
        self.gdb.execute("set $ZF = 6 ")
        self.gdb.execute("set $eflags &= ~(1 << $ZF)")
        return

    def display_flag(self):
        # Clean the screen to format the output.
        # The only purpose of this is to simulate what
        #   liveoverflow did with radare2 & r2pipe.
        self.gdb.execute("shell clear")
        _flag = ""
        for c in self.flag:
            if c >= ord('0') and c <= ord('~'):
                _flag += chr(c)
            else:
                _flag += " "
        self.pre_flag = _flag
        sys.stdout.write(self.pre_flag + "\n")
        sys.stdout.flush()
        return


solver = GdbSolver()
solver.start()
solver.solve()

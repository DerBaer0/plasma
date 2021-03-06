#!/usr/bin/env python3
#
# PLASMA : Generate an indented asm code (pseudo-C) with colored syntax.
# Copyright (C) 2015    Joel
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.    If not, see <http://www.gnu.org/licenses/>.
#

import threading
from queue import Queue

from plasma.lib.utils import unsigned
from plasma.lib.fileformat.binary import T_BIN_PE, T_BIN_ELF
from plasma.lib.memory import MEM_CODE, MEM_FUNC, MEM_UNK, MEM_ASCII, MEM_OFFSET

# database.functions[ADDR] contains a list, here are the indexes
FUNC_END = 0
FUNC_FLAGS = 1
FUNC_VARS = 2
FUNC_ID = 3

VAR_TYPE = 0
VAR_NAME = 1

FUNC_FLAG_NORETURN = 1


NORETURN_ELF = {
    "exit", "_exit", "__stack_chk_fail",
    "abort", "__assert_fail", "__libc_start_main",
}

NORETURN_PE = {
    "exit", "ExitProcess", "_exit", "quick_exit", "_Exit", "abort"
}



# TODO: generic way, some functions are copied or a bit
# modified from lib.disassembler


class Analyzer(threading.Thread):
    def init(self):
        self.dis = None
        self.msg = Queue()
        self.pending = set() # prevent recursive call
        self.pending_not_curr = set() # prevent big stack

        self.running_second_pass = False
        self.where = 0 # cursor when parsing memory
        self.second_pass_done = False


    def set(self, gctx):
        self.gctx = gctx
        self.dis = gctx.dis
        self.db = gctx.db
        self.api = gctx.api
        self.ARCH_UTILS = self.gctx.libarch.utils

        self.CS_OP_IMM = self.dis.capstone.CS_OP_IMM
        self.CS_OP_MEM = self.dis.capstone.CS_OP_MEM

        # TODO: move arch dependant in lib/arch

        if self.dis.is_x86:
            from capstone.x86 import (X86_REG_EIP, X86_REG_RIP,
                                      X86_REG_EBP, X86_REG_RBP)
            self.X86_REG_EIP = X86_REG_EIP
            self.X86_REG_RIP = X86_REG_RIP
            self.X86_REG_RBP = X86_REG_RBP
            self.X86_REG_EBP = X86_REG_EBP

        elif self.dis.is_mips:
            from capstone.mips import MIPS_REG_GP
            self.MIPS_REG_GP = MIPS_REG_GP

        elif self.dis.is_arm:
            from capstone.arm import ARM_REG_PC
            self.ARM_REG_PC = ARM_REG_PC

        # cache
        self.is_ret = self.ARCH_UTILS.is_ret
        self.is_jump = self.ARCH_UTILS.is_jump
        self.is_uncond_jump = self.ARCH_UTILS.is_uncond_jump
        self.is_cond_jump = self.ARCH_UTILS.is_cond_jump
        self.is_call = self.ARCH_UTILS.is_call
        self.disasm = self.dis.lazy_disasm
        self.jmptables = self.db.jmptables
        self.functions = self.db.functions
        self.prologs = self.ARCH_UTILS.PROLOGS


    def __add_prefetch(self, addr_set, inst):
        if self.dis.is_mips:
            prefetch = self.disasm(inst.address + inst.size)
            if prefetch is not None:
                addr_set[prefetch.address] = prefetch
            return prefetch
        return None


    def import_flags(self, ad):
        # Check all known functions which never return
        if ad not in self.dis.binary.imports:
            return 0
        name = self.db.reverse_symbols[ad]
        if self.dis.binary.type == T_BIN_PE:
            return FUNC_FLAG_NORETURN if name in NORETURN_PE else 0
        elif self.dis.binary.type == T_BIN_ELF:
            return FUNC_FLAG_NORETURN if name in NORETURN_ELF else 0
        return 0


    def run(self):
        while 1:
            item = self.msg.get()

            if isinstance(item, tuple):
                if self.dis is not None:
                    # Run analysis
                    (ad, entry_is_func, force, add_if_code, queue_response) = item
                    self.analyze_flow(ad, entry_is_func, force, add_if_code)

                    # Send a notification
                    if queue_response is not None:
                        queue_response.put(1)

            elif isinstance(item, str):
                if item == "exit":
                    break

                if item == "pass_scan_mem":
                    if not self.second_pass_done and self.msg.qsize() == 0:
                        self.second_pass_done = True
                        self.running_second_pass = True
                        self.pass_detect_unk_data()
                        self.pass_detect_functions()
                        self.running_second_pass = False
                    else:
                        self.msg.put(item)


    def pass_detect_unk_data(self):
        b = self.dis.binary
        mem = self.db.mem
        wait = Queue()

        for s in b.iter_sections():
            if s.is_exec:
                continue

            ad = s.start
            end = ad + s.real_size

            while ad < end:
                self.where = ad

                if not mem.is_unk(ad):
                    ad += mem.get_size(ad)
                    continue

                val = s.read_int(ad, self.dis.wordsize)

                # Detect if it's an address
                if val is not None:
                    s2 = b.get_section(val)
                    if s2 is not None and s2.is_exec:
                        self.api.add_xref(ad, val)
                        self.db.mem.add(ad, self.dis.wordsize, MEM_OFFSET)
                        ad += self.dis.wordsize

                        if not self.db.mem.exists(val):
                            self.db.mem.add(val, self.dis.wordsize, MEM_UNK)

                            # Do an analysis on this value.
                            if val not in self.pending and \
                                    val not in self.pending_not_curr and \
                                    self.first_inst_are_code(val):
                                self.analyze_flow(val, self.has_prolog(val), False, True)
                        continue

                # Detect if it's a string
                n = b.is_string(ad, s=s)
                if n != 0:
                    self.db.mem.add(ad, n, MEM_ASCII)
                    ad += n
                    continue

                ad += 1


    def pass_detect_functions(self):
        b = self.dis.binary
        mem = self.db.mem

        for s in b.iter_sections():
            if not s.is_exec:
                continue

            ad = s.start
            end = ad + s.real_size

            while ad < end:
                self.where = ad

                if not mem.is_unk(ad):
                    ad += mem.get_size(ad)
                    continue

                # Do an analysis on this value.
                # Don't run first_inst_are_code, it's too slow on big sections.
                if ad not in self.pending and self.has_prolog(ad):
                    # Don't push, run directly the analyzer. Otherwise
                    # we will re-analyze next instructions.
                    self.analyze_flow(ad, True, False, True)

                ad += 1


    # Check if the five first instructions can be disassembled.
    # Each instruction must be different of null bytes.
    def first_inst_are_code(self, ad):
        for i in range(5):
            inst = self.disasm(ad)
            if inst is None:
                return False
            if inst.bytes.count(0) == len(inst.bytes):
                return False
            ad += inst.size
        return True


    # This function tries to optimize calls to lazy_disasm.
    def has_prolog(self, ad):
        match = False
        buf = self.dis.binary.read(ad, 4)

        if buf is None:
            return False

        if not self.dis.is_big_endian:
            buf = bytes(reversed(buf))

        for lst in self.prologs:
            for p in lst:
                if buf.startswith(p):
                    match = True
                    break

        if not match:
            return False

        inst = self.disasm(ad)
        if inst is None:
            return False

        # Don't disassemble the second instruction, just get a copy of bytes.
        buf = self.dis.binary.read(ad + inst.size, 4)

        if not self.dis.is_big_endian:
            buf = bytes(reversed(buf))

        for lst in self.prologs:
            for p in lst:
                if buf.startswith(p[inst.size:]):
                    return True

        return False


    def analyze_operands(self, i, func_obj):
        b = self.dis.binary

        for op in i.operands:
            if op.type == self.CS_OP_IMM:
                val = unsigned(op.value.imm)

            elif op.type == self.CS_OP_MEM and op.mem.disp != 0:

                if self.dis.is_x86:
                    if op.mem.segment != 0:
                        continue
                    if op.mem.index == 0:
                        # Compute the rip register
                        if op.mem.base == self.X86_REG_EIP or \
                            op.mem.base == self.X86_REG_RIP:
                            val = i.address + i.size + unsigned(op.mem.disp)

                        # Check if it's a stack variable
                        elif (op.mem.base == self.X86_REG_EBP or \
                              op.mem.base == self.X86_REG_RBP):
                            if func_obj is not None:
                                ty = self.db.mem.find_type(op.size)
                                func_obj[FUNC_VARS][op.mem.disp] = [ty, None]
                            # Continue the loop !!
                            continue
                        else:
                            val = unsigned(op.mem.disp)
                    else:
                        val = unsigned(op.mem.disp)

                # TODO: stack variables for arm/mips

                elif self.dis.is_arm:
                    if op.mem.index == 0 and op.mem.base == self.ARM_REG_PC:
                        val = i.address + i.size * 2 + op.mem.disp
                    else:
                        val = op.mem.disp

                elif self.dis.is_mips:
                    if op.mem.base == self.MIPS_REG_GP:
                        if self.dis.mips_gp == -1:
                            continue
                        val = op.mem.disp + self.dis.mips_gp
                    else:
                        val = op.mem.disp
            else:
                continue

            s = b.get_section(val)
            if s is None or s.start == 0:
                continue

            self.api.add_xref(i.address, val)

            if not self.db.mem.exists(val):
                sz = op.size if self.dis.is_x86 else self.dis.wordsize
                deref = s.read_int(val, sz)

                # If (*val) is an address
                if deref is not None and b.is_address(deref):
                    ty = MEM_OFFSET
                    self.api.add_xref(val, deref)

                    if not self.db.mem.exists(deref):
                        self.db.mem.add(deref, 1, MEM_UNK)

                        # Do an anlysis on this value.
                        if deref not in self.pending and \
                                deref not in self.pending_not_curr and \
                                self.first_inst_are_code(deref):

                            self.pending_not_curr.add(deref)
                            self.msg.put(
                                (deref, self.has_prolog(deref), False, True, None))
                else:
                    # Check if this is an address to a string
                    sz = b.is_string(val)
                    if sz != 0:
                        ty = MEM_ASCII
                    else:
                        sz = op.size if self.dis.is_x86 else self.dis.wordsize
                        if op.type == self.CS_OP_MEM:
                            ty = self.db.mem.find_type(sz)
                        else:
                            ty = MEM_UNK

                self.db.mem.add(val, sz, ty)

                if ty == MEM_UNK:
                    # Do an analysis on this value, if this is not code
                    # nothing will be done.
                    # jumps and calls are already analyzed in analyze_flow.
                    if val not in self.pending and \
                            not (self.is_jump(i) or self.is_call(i)) and \
                            val not in self.pending_not_curr and \
                            self.first_inst_are_code(val):

                        self.pending_not_curr.add(val)
                        self.msg.put(
                            (val, self.has_prolog(val), False, True, None))


    def __add_analyzed_code(self, mem, entry, inner_code, entry_is_func, flags):
        is_def = entry in self.functions
        if entry_is_func or is_def:
            # It can be None because when symbols are loaded functions are
            # set to None initially.
            if is_def and self.functions[entry] is not None:
                last_end = self.functions[entry][FUNC_END]
                self.db.end_functions[last_end].remove(entry)
                if not self.db.end_functions[last_end]:
                    del self.db.end_functions[last_end]

            e = max(inner_code) if inner_code else -1
            func_id = self.db.func_id_counter
            func_obj = [e, flags, {}, func_id]
            self.functions[entry] = func_obj
            self.db.func_id[func_id] = entry
            self.db.func_id_counter += 1

            if e in self.db.end_functions:
                self.db.end_functions[e].append(entry)
            else:
                self.db.end_functions[e] = [entry]

        else:
            func_id = -1
            func_obj = None

        for ad, inst in inner_code.items():
            self.analyze_operands(inst, func_obj)

            if ad == entry and func_id != -1:
                mem.add(ad, inst.size, MEM_FUNC, func_id)
            else:
                mem.add(ad, inst.size, MEM_CODE, func_id)

            if ad in self.db.reverse_symbols:
                name = self.db.reverse_symbols[ad]
                if name.startswith("ret_") or name.startswith("loop_"):
                    self.api.rm_symbol(ad)


    def is_noreturn(self, ad, entry):
        return ad != entry and self.functions[ad][FUNC_FLAGS] & FUNC_FLAG_NORETURN


    #
    # analyze_flow:
    # entry             address of the code to analyze.
    # entry_is_func     if true a function will be created, otherwise
    #                   instructions will be set only as "code".
    # force             if true and entry is already functions, the analysis
    #                   is forced.
    # add_if_code       if true, it means that we are not sure that entry is an
    #                   address to a code location. In this case, if the control
    #                   flow contains a bad instruction, the functions or
    #                   instructions will not be added.
    #
    def analyze_flow(self, entry, entry_is_func, force, add_if_code):
        if entry in self.pending_not_curr:
            self.pending_not_curr.remove(entry)

        if entry in self.pending:
            return

        if not force:
            # TODO check that we don't go inside an instruction
            if not entry_is_func and self.db.mem.is_loc(entry) or \
                    entry_is_func and self.db.mem.is_func(entry):
                return

            # Check if is not inside a function
            if self.db.mem.get_func_id(entry) != -1:
                return

        mem = self.db.mem

        if mem.is_inside_mem(entry):
            return

        self.pending.add(entry)

        inner_code = {} # ad -> capstone instruction

        is_pe_import = False

        # Check if it's a jump to an imported symbol
        # jmp *(IMPORT)
        if self.dis.binary.type == T_BIN_PE:
            if entry in self.dis.binary.imports:
                is_pe_import = True
                flags = self.import_flags(entry)
            else:
                inst = self.dis.lazy_disasm(entry)
                if inst is not None:
                    ptr = self.dis.binary.reverse_stripped(self.dis, inst)
                    if ptr != -1:
                        inner_code[inst.address] = inst
                        flags = self.import_flags(ptr)

        if not is_pe_import and not inner_code:
            flags = self.__sub_analyze_flow(entry, inner_code, add_if_code)

        if inner_code and flags != -1:
            self.__add_analyzed_code(self.db.mem, entry, inner_code,
                                     entry_is_func, flags)

        inner_code.clear()
        self.pending.remove(entry)


    def __sub_analyze_flow(self, entry, inner_code, add_if_code):
        if self.dis.binary.get_section(entry) is None:
            return -1

        stack = [entry]
        has_ret = False

        # If entry is not "code", we have to rollback added xrefs
        has_bad_inst = False
        if add_if_code:
            added_xrefs = []

        while stack:
            ad = stack.pop()
            inst = self.disasm(ad)

            if inst is None:
                has_bad_inst = True
                if add_if_code:
                    break
                continue

            if ad in inner_code:
                continue

            inner_code[ad] = inst

            if self.is_ret(inst):
                self.__add_prefetch(inner_code, inst)
                has_ret = True

            elif self.is_uncond_jump(inst):
                self.__add_prefetch(inner_code, inst)

                op = inst.operands[-1]

                if op.type == self.CS_OP_IMM:
                    nxt = unsigned(op.value.imm)
                    self.api.add_xref(ad, nxt)
                    if self.db.mem.is_func(nxt):
                        has_ret = not self.is_noreturn(nxt, entry)
                    else:
                        stack.append(nxt)
                    if add_if_code:
                        added_xrefs.append((ad, nxt))
                else:
                    if inst.address in self.jmptables:
                        table = self.jmptables[inst.address].table
                        stack += table
                        self.api.add_xref(ad, table)
                        if add_if_code:
                            added_xrefs.append((ad, table))
                    else:
                        # TODO
                        # This is a register or a memory access
                        # we can't say if the function really returns
                        has_ret = True

            elif self.is_cond_jump(inst):
                prefetch = self.__add_prefetch(inner_code, inst)

                op = inst.operands[-1]
                if op.type == self.CS_OP_IMM:
                    if prefetch is None:
                        direct_nxt = inst.address + inst.size
                    else:
                        direct_nxt = prefetch.address + prefetch.size

                    nxt_jmp = unsigned(unsigned(op.value.imm))
                    self.api.add_xref(ad, nxt_jmp)
                    stack.append(direct_nxt)

                    if add_if_code:
                        added_xrefs.append((ad, nxt_jmp))

                    if self.db.mem.is_func(nxt_jmp):
                        has_ret = not self.is_noreturn(nxt_jmp, entry)
                    else:
                        stack.append(nxt_jmp)

            elif self.is_call(inst):
                op = inst.operands[-1]
                if op.type == self.CS_OP_IMM:
                    imm = unsigned(op.value.imm)
                    self.api.add_xref(ad, imm)

                    if add_if_code:
                        added_xrefs.append((ad, imm))

                    if not self.db.mem.is_func(imm):
                        self.analyze_flow(imm, True, False, add_if_code)

                    if self.db.mem.is_func(imm) and self.is_noreturn(imm, entry):
                        self.__add_prefetch(inner_code, inst)
                        continue

                nxt = inst.address + inst.size
                stack.append(nxt)

            else:
                nxt = inst.address + inst.size
                stack.append(nxt)

        if add_if_code and has_bad_inst:
            for from_ad, to_ad in added_xrefs:
                self.api.rm_xrefs(from_ad, to_ad)
            return -1

        # for ELF
        if entry in self.dis.binary.imports:
            flags = self.import_flags(entry)
        elif has_ret:
            flags = 0
        else:
            flags = FUNC_FLAG_NORETURN

        return flags

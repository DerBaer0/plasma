#!/bin/python3
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

class ICode:
	def __init__(self, csInsn):
		self.insn = csInsn
		self.highLevel = dict() # 'high level' code string for each register (dict)

class ICALL(ICode):
    def __init__(self, csInsn):
        ICode.__init__(self, csInsn)
        self.numArgs = -1

class IMUL(ICode):
    pass

class IMOV(ICode):
	pass

class ILEA(ICode):
    pass

class IJMP(ICode):
	pass

class IARITH(ICode):
	def __init__(self, csInsn, typ):
		ICode.__init__(self, csInsn)
		self.typ = typ


class Ast_CodeBlock:
	def __init__(self, ics):
		self.icodes = ics


class Ast_Branch:
    def __init__(self):
        self.nodes = []
        self.parent = None
        self.level = 0
        self.idx_in_parent = -1 # index in nodes list in the parent branch

    def add(self, node):
        if isinstance(node, Ast_Branch):
            self.nodes += node.nodes
        else:
            self.nodes.append(node)


class Ast_IfGoto:
    def __init__(self, orig_jump, cond_id, addr_jump, prefetch=None):
        self.orig_jump = orig_jump
        self.cond_id = cond_id
        self.addr_jump = addr_jump
        self.fused_inst = None
        self.prefetch = prefetch
        self.parent = None
        self.level = 0


class Ast_AndIf:
    def __init__(self, orig_jump, cond_id, expected_next_addr, prefetch=None):
        self.orig_jump = orig_jump
        self.cond_id = cond_id
        self.fused_inst = None
        self.prefetch = prefetch
        self.parent = None
        self.level = 0
        self.expected_next_addr = expected_next_addr


# This is used for ARM to fuse instructions which have the same condition
class Ast_If_cond:
    def __init__(self, cond_id, br):
        self.cond_id = cond_id
        self.br = br
        self.fused_inst = None
        self.parent = None
        self.level = 0


class Ast_Ifelse:
    def __init__(self, jump_inst, br_next_jump, br_next,
                 expected_next_addr, prefetch=None):
        self.jump_inst = jump_inst
        self.br_next = br_next
        self.br_next_jump = br_next_jump
        self.fused_inst = None
        self.prefetch = prefetch
        self.parent = None
        self.level = 0
        self.expected_next_addr = expected_next_addr


class Ast_Goto:
    def __init__(self, addr):
        self.addr_jump = addr
        self.parent = None
        self.level = 0

        # The algorithm can add some goto and remove some of them
        # if they are unnecessary. But sometimes, goto are added
        # for more readability, so set to True to keep them.
        self.dont_remove = False


class Ast_Loop:
    def __init__(self):
        self.branch = Ast_Branch()
        self.is_infinite = False
        self.parent = None
        self.level = 0

    def add(self, node):
        self.branch.add(node)

    def set_infinite(self, v):
        self.is_infinite = v

    def set_branch(self, b):
        self.branch = b


# ONLY FOR DEBUG !!
class Ast_Comment:
    def __init__(self, text):
        self.text = text
        self.parent = None
        self.level = 0
        self.nodes = []

from plasma.lib.visitors.visitor import *
from plasma.lib.ast import *
from plasma.lib.ops import *
from plasma.lib.arch.x86.utils import OPPOSITES

from capstone.x86 import *

class DumpVisitor:
	def __init__(self, out, gctx=None):
		self.o = out
		self.topLevel = True # after the first instructions, drop this (used to determine the prolog)
		self.regName = {
			X86_REG_RAX: "rax",
			X86_REG_RBX: "rbx",
			X86_REG_RCX: "rcx",
			X86_REG_RDX: "rdx",
			X86_REG_RDI: "rdi",
			X86_REG_RSI: "rsi",
			X86_REG_R8: "r8",
			X86_REG_R9: "r9"
		}
		self.BIGS = {
			# RDI
			X86_REG_RDI: X86_REG_RDI,
			X86_REG_EDI: X86_REG_RDI,
			# RSI
			X86_REG_RSI: X86_REG_RSI,
			X86_REG_ESI: X86_REG_RSI,
			# RDX
			X86_REG_RDX: X86_REG_RDX,
			X86_REG_EDX: X86_REG_RDX,
			X86_REG_DX: X86_REG_RDX,
			X86_REG_DL: X86_REG_RDX,
			# RCX
			X86_REG_RCX: X86_REG_RCX,
			X86_REG_ECX: X86_REG_RCX,
			X86_REG_CX: X86_REG_RCX,
			X86_REG_CL: X86_REG_RCX,
			# RAX
			X86_REG_RAX: X86_REG_RAX,
			X86_REG_EAX: X86_REG_RAX,
			X86_REG_AX: X86_REG_RAX,
			X86_REG_AL: X86_REG_RAX,
			# RBX
			X86_REG_RBX: X86_REG_RBX,
			X86_REG_EBX: X86_REG_RBX,
			X86_REG_BX: X86_REG_RBX,
			X86_REG_BL: X86_REG_RBX
		}
		self.argRegs = [X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX, X86_REG_R8, X86_REG_R9]
		self.gctx = gctx
		self.printEveryLine = gctx.show_debug
		self.exit = -1

	@visitor(Ast_CodeBlock, int)
	def visit(self, node, tab):
		for n in node.icodes:
			# do already mapped instructions by myself
			# and only print code for instructinos with sideeffects (mem, call)
			noLine = False
			if isinstance(n, ICALL):
				self.o._tabs(tab)
				self.o._add(str(n.retArg) + " = ")

				self.o._operand(n.insn, 0, hexa=True, force_dont_print_data=True)
				self.o._add("(")
				if n.numArgs > 0:
					if isinstance(n.prev.highLevel[self.argRegs[0]], str):
						self.o._add(n.prev.highLevel[self.argRegs[0]])
					else:
						n.prev.highLevel[self.argRegs[0]].writeOut(self.o)
					for i in range(1, n.numArgs):
						self.o._add(", ")
						if isinstance(n.prev.highLevel[self.argRegs[i]], str):
							self.o._add(n.prev.highLevel[self.argRegs[i]])
						else:
							n.prev.highLevel[self.argRegs[i]].writeOut(self.o)
				self.o._add(")")
			elif isinstance(n, IMOV):
				# if writing to memory
				if n.insn.operands[0].type == X86_OP_MEM:
					self.o._tabs(tab)
					self.o._operand(n.insn, 0)
					self.o._add(" := ")
					if n.insn.operands[1].type == X86_OP_REG:
						src = self.BIGS[n.insn.operands[1].reg]
						# FIXME should be n.pref.highLevel, but this is an empty set ...
						n.highLevel[src].writeOut(self.o)
					elif n.insn.operands[1].type == X86_OP_IMM:
						self.o._imm(n.insn.operands[1].imm, 1, hexa=True)
					else:
						assert(False)
#					self.o._asm_inst(n.insn, tab)
				else:
					if self.printEveryLine:
						noLine = False
						self.o._add("#")
						self.o._asm_inst(n.insn, tab)
					else:
						noLine = True
			elif isinstance(n, IJMP):
				if n.insn.operands[-1].imm == self.exit:
					self.o._tabs(tab)
					self.o._keyword("return")
					self.o._add(" ")
					print(n.highLevel[X86_REG_RAX])
					n.highLevel[X86_REG_RAX].writeOut(self.o)
			else:
				if self.printEveryLine:
					noLine = False
					self.o._add("#")
					self.o._asm_inst(n.insn, tab)
				else:
					noLine = True

			if self.printEveryLine:
				self.o._new_line()
				self.o._tabs(tab+1)
				for i in n.highLevel:
					if (not isinstance(n.highLevel[i], UnknownOp)) and (n.prev == None or (not i in n.prev.highLevel) or n.highLevel[i] != n.prev.highLevel[i]):
						if i in self.regName:
							self.o._add(self.regName[i] + " = ")
						else:
							self.o._add(i + " = ")
						self.o._string("\"" + str(n.highLevel[i]) + "\"")
						self.o._add(", ")

			if not noLine:
				self.o._new_line()

	@visitor(Ast_Branch, int)
	def visit(self, node, tab):
		if self.exit == -1: # we are at the top level and didn't find the return code
			self.exit = node.nodes[-1].icodes[0].insn.address
		for n in node.nodes:
#			self.o._add(">>" + str(tab) + "\t" + str(n))
#			self.o._new_line()
			self.visit(n, tab)

	@visitor(Ast_IfGoto, int)
	def visit(self, node, tab):
#		self.o._comment_fused(node.orig_jump, node.fused_inst, tab)
		if node.prefetch is not None:
			self.o._asm_inst(node.prefetch, tab)
		self.o._tabs(tab)
		self.o._keyword("if ")
		self.o._if_cond(node.cond_id, node.fused_inst)
		self.o._keyword("  goto ")
		self.o._label_or_address(node.addr_jump, -1, False)
		self.o._new_line()

	@visitor(Ast_AndIf, int)
	def visit(self, node, tab):
#		self.o._comment_fused(node.orig_jump, node.fused_inst, tab)
		if node.prefetch is not None:
			self.o._asm_inst(node.prefetch, tab)
		self.o._tabs(tab)
		self.o._keyword("and ")
		self.o._keyword("if ")
		self.o._if_cond(node.cond_id, node.fused_inst)
		self.o._new_line()

	@visitor(Ast_If_cond, int)
	def visit(self, node, tab):
#		self.o._comment_fused(None, node.fused_inst, tab)
		self.o._tabs(tab)
		self.o._keyword("if ")
		self.o._if_cond(node.cond_id, node.fused_inst)
		self.o._add(" {")
		self.o._new_line()
		self.visit(node.br, tab+1)
		self.o._tabs(tab)
		self.o._add("}")
		self.o._new_line()

	@visitor(Ast_Ifelse, int)
	def visit(self, node, tab):
		ARCH_UTILS = self.o.gctx.libarch.utils

		#
		# if cond {
		# } else {
		#   ...
		# }
		#
		# become
		#
		# if !cond {
		#   ...
		# }
		#

		br_next = node.br_next
		br_next_jump = node.br_next_jump
		inv_if = False

		if len(node.br_next.nodes) == 0:
			br_next, br_next_jump = br_next_jump, br_next
			inv_if = True

#		self.o._comment_fused(node.jump_inst, node.fused_inst, tab)

		if node.prefetch is not None:
			self.o._asm_inst(node.prefetch, tab)

		self.o._tabs(tab)
		# TODO
		self.o._keyword("if ")
		#if print_else_keyword:
		#	self.o._keyword("else if ")
		#else:
		#	self.o._keyword("if ")

		# jump_inst is the condition to go to the else-part
		if inv_if:
			self.o._if_cond(ARCH_UTILS.get_cond(node.jump_inst),
							node.fused_inst)
		else:
			self.o._if_cond(ARCH_UTILS.invert_cond(node.jump_inst),
							node.fused_inst)

		self.o._add(" {")
		self.o._new_line()

		# if-part
		self.visit(br_next, tab+1)
		self.o._tabs(tab)
		self.o._add("}")

		# else-part
		if len(br_next_jump.nodes) > 0:
			#
			# if {
			#   ...
			# } else {
			#   if {
			#	 ...
			#   }
			# }
			#
			# become :
			#
			# if {
			#   ...
			# }
			# else if {
			#   ...
			# }
			#

			br = br_next_jump

			if len(br.nodes) == 1 and isinstance(br.nodes[0], Ast_Ifelse):
				self.o._new_line()
				self.visit(br.nodes[0], tab, print_else_keyword=True)
				return

			if len(br.nodes) == 2 and isinstance(br.nodes[0], list) and \
				  len(br.nodes[0]) == 1 and ARCH_UTILS.is_cmp(br.nodes[0][0]) and \
				  isinstance(br.nodes[1], Ast_Ifelse):
				self.o._new_line()
				self.visit(br.nodes[1], tab)
				return

			self.o._keyword(" else")
			self.o._add(" {")
			self.o._new_line()
			self.visit(br, tab+1)

			self.o._tabs(tab)
			self.o._add("}")

		self.o._new_line()

	@visitor(Ast_Goto, int)
	def visit(self, node, tab):
		self.o._tabs(tab)
		self.o._keyword("goto ")
		self.o._label_or_address(node.addr_jump, -1, False)
		self.o._new_line()

	@visitor(Ast_Loop, int)
	def visit(self, node, tab):
		self.o._tabs(tab)
		if node.is_infinite:
			self.o._keyword("for")
			self.o._add(" (;;) {")
		else:
			self.o._keyword("while")
			self.o._add(" ")
			# First instruction is a IfGoto (probably the while condition)
			if isinstance(node.branch.nodes[1], Ast_IfGoto):
				ifgoto = node.branch.nodes[1]
				# TODO: check if jump goes after the loop
				# this is really
				self.o._if_cond(OPPOSITES.get(ifgoto.cond_id, -1), ifgoto.fused_inst)
				# finish remaining blocks (omitting this conditional)
				self.o._add(" {")
				self.o._new_line()
				for n in node.branch.nodes[2:]:
					if isinstance(n, list):
						self.o._asm_block(n, tab+1)
					else: # ast
						self.visit(n, tab+1)
				self.o._tabs(tab)
				self.o._add("}")
				self.o._new_line()
				return
			# else is an unconditional loop (break somewhere inside probably)
			self.o._add("(1)")
			self.o._add(" {")
		self.o._new_line()
		self.visit(node.branch, tab+1)
		self.o._tabs(tab)
		self.o._add("}")
		self.o._new_line()

	@visitor(Ast_Comment, int)
	def visit(self, node, tab):
		pass #print( "Comment")

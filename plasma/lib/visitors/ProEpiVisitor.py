from plasma.lib.visitors.visitor import *
from plasma.lib.ast import *
from plasma.lib.arch.x86.utils import is_pop, is_push

from capstone.x86 import (X86_INS_MOV, X86_INS_SUB,
		X86_REG_RBP, X86_REG_RSP)

# strips the prolog and epilog
class ProEpiVisitor:
	def __init__(self, gctx=None):
		self.gctx = gctx
		self.stackSize = -1
		self.firstCodeBlock = True

	@visitor(Ast_CodeBlock)
	def visit(self, node):
		if self.firstCodeBlock:
			# drop the first if it is a 'pop'
			ic = node.icodes[0]
			if is_push(ic.insn):
				node.icodes = node.icodes[1:]
				# drop the first if it is a 'rbp = rsp'
				ic = node.icodes[0]

				if ic.insn.id == X86_INS_MOV and len(ic.insn.operands) == 2 \
						and ic.insn.operands[0].reg == X86_REG_RBP and ic.insn.operands[1].reg == X86_REG_RSP:
					node.icodes = node.icodes[1:]
					# drop the first if it is a 'rsp -= x'
					ic = node.icodes[0]
					if ic.insn.id == X86_INS_SUB and ic.insn.operands[0].reg == X86_REG_RSP:
						self.stackSize = ic.insn.operands[1].imm
						node.icodes = node.icodes[1:]
			self.firstCodeBlock = False

	@visitor(Ast_Branch)
	def visit(self, node):
		for n in node.nodes:
			self.visit(n)

	@visitor(Ast_IfGoto)
	def visit(self, node):
		pass

	@visitor(Ast_AndIf)
	def visit(self, node):
		pass

	@visitor(Ast_If_cond)
	def visit(self, node):
		self.visit(node.br)

	@visitor(Ast_Ifelse)
	def visit(self, node):
		# if-part
		self.visit(node.br_next)
		br = node.br_next_jump
		if len(br.nodes) == 1 and isinstance(br.nodes[0], Ast_Ifelse):
			self.visit(br.nodes[0])
			return

		if len(br.nodes) == 2 and isinstance(br.nodes[0], list) and \
			  len(br.nodes[0]) == 1 and self.gctx.libarch.utils.is_cmp(br.nodes[0][0]) and \
			  isinstance(br.nodes[1], Ast_Ifelse):
			self.visit(br.nodes[1])
			return

		self.visit(br)

	@visitor(Ast_Goto)
	def visit(self, node):
		pass

	@visitor(Ast_Loop)
	def visit(self, node):
		self.visit(node.branch)

	@visitor(Ast_Comment)
	def visit(self, node):
		pass #print( "Comment")

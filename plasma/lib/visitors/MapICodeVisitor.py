from plasma.lib.visitors.visitor import *
from plasma.lib.ast import *

from capstone.x86 import *

# Changes hacky asm blocks from capstone to a Ast_CodeBlock node
class MapICodeVisitor:
	def __init__(self, gctx=None):
				self.gctx = gctx

	def translate(self, insn):
		# Moves
		if insn.id == X86_INS_MOV or insn.id == X86_INS_MOVABS:
			return IMOV(insn)
		if insn.id == X86_INS_MOVZX:
			return IMOVZX(insn)
		if insn.id == X86_INS_MOVSXD:
			return IMOVSXD(insn)

		# Arithmetic
		if insn.id == X86_INS_ADD:
			return IARITH(insn, "+")
		if insn.id == X86_INS_SUB:
			return IARITH(insn, "-")
		if insn.id == X86_INS_XOR:
			return IARITH(insn, "^")
		if insn.id == X86_INS_IMUL or insn.id == X86_INS_MUL:
			return IMUL(insn)
		if insn.id == X86_INS_SHR:
			return ISHR(insn)
		if insn.id == X86_INS_SHL:
			return ISHL(insn)

		# Jumps
		if insn.id == X86_INS_JMP:
			return IJMP(insn)

		# Misc
		if insn.id == X86_INS_CALL:
			return ICALL(insn)
		if insn.id == X86_INS_LEA:
			return ILEA(insn)
		return ICode(insn)

	@visitor(Ast_CodeBlock)
	def visit(self, node):
		pass

	@visitor(Ast_Branch)
	def visit(self, node):
		for i in range(len(node.nodes)):
			if isinstance(node.nodes[i], list):
				icodes = [self.translate(ins) for ins in node.nodes[i]]
				# create prev linkage
				last = None
				for ic in icodes:
					ic.prev = last
					last =  ic
				if i > 0 and isinstance(node.nodes[i-1], Ast_CodeBlock):
					icodes[0].prev = node.nodes[i-1].icodes[-1]
					node.nodes[i-1].icodes += icodes
					node.nodes[i] = Ast_CodeBlock([])
				else:
					node.nodes[i] = Ast_CodeBlock(icodes)
			else: # ast
				self.visit(node.nodes[i])

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

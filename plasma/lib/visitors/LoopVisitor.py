from plasma.lib.visitors.visitor import *
from plasma.lib.ast import *

class LoopVisitor:
	def __init__(self, gctx=None):
		self.gctx = gctx
		self.loopB = 0

	@visitor(Ast_CodeBlock, bool, int)
	def visit(self, node, firstInLoop, loopBegin):
		pass

	@visitor(Ast_Branch, bool, int)
	def visit(self, node, firstInLoop, loopBegin):
		for n in node.nodes:
			if isinstance(n, list):
				if firstInLoop:
#					print("LoopBeegin 0x%x\n" % n[0].address)
					self.loopB = n[0].address
					firstInLoop = False
#				self.o._asm_block(n, tab)
			else: # ast
				self.visit(n, False, loopBegin)

	@visitor(Ast_IfGoto, bool, int)
	def visit(self, node, firstInLoop, loopBegin):
		pass

	@visitor(Ast_AndIf, bool, int)
	def visit(self, node, firstInLoop, loopBegin):
		pass

	@visitor(Ast_If_cond, bool, int)
	def visit(self, node, firstInLoop, loopBegin):
		self.visit(node.br, False, loopBegin)

	@visitor(Ast_Ifelse, bool, int)
	def visit(self, node, firstInLoop, loopBegin):
		# if-part
		self.visit(node.br_next, False, loopBegin)
		br = node.br_next_jump
		if len(br.nodes) == 1 and isinstance(br.nodes[0], Ast_Ifelse):
			self.visit(br.nodes[0], False, loopBegin)
			return

		if len(br.nodes) == 2 and isinstance(br.nodes[0], list) and \
			  len(br.nodes[0]) == 1 and self.gctx.libarch.utils.is_cmp(br.nodes[0][0]) and \
			  isinstance(br.nodes[1], Ast_Ifelse):
			self.visit(br.nodes[1], False, loopBegin)
			return

		self.visit(br, False, loopBegin)

	@visitor(Ast_Goto, bool, int)
	def visit(self, node, firstInLoop, loopBegin):
		pass

	@visitor(Ast_Loop, bool, int)
	def visit(self, node, firstInLoop, loopBegin):
		self.visit(node.branch, True, 0)

	@visitor(Ast_Comment, bool, int)
	def visit(self, node, firstInLoop, loopBegin):
		pass #print( "Comment")

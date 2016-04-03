from plasma.lib.visitors.visitor import *
from plasma.lib.ast import *

class DumpVisitor:
	def __init__(self, out):
		self.o = out

	@visitor(Ast_Branch, int)
	def visit(self, node, tab):
		for n in node.nodes:
			if isinstance(n, list):
				self.o._asm_block(n, tab)
			else: # ast
				self.visit(n, tab)

	@visitor(Ast_IfGoto, int)
	def visit(self, node, tab):
		self.o._comment_fused(node.orig_jump, node.fused_inst, tab)
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
		self.o._comment_fused(node.orig_jump, node.fused_inst, tab)
		if node.prefetch is not None:
			self.o._asm_inst(node.prefetch, tab)
		self.o._tabs(tab)
		self.o._keyword("and ")
		self.o._keyword("if ")
		self.o._if_cond(node.cond_id, node.fused_inst)
		self.o._new_line()

	@visitor(Ast_If_cond, int)
	def visit(self, node, tab):
		self.o._comment_fused(None, node.fused_inst, tab)
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
		ARCH_UTILS = o.gctx.libarch.utils

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

		o._comment_fused(node.jump_inst, node.fused_inst, tab)

		if node.prefetch is not None:
			self.o._asm_inst(node.prefetch, tab)

		self.o._tabs(tab)
		if print_else_keyword:
			self.o._keyword("else if ")
		else:
			self.o._keyword("if ")

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
				self.visit(br.nodes[1], tab, print_else_keyword=True)
				return

			self.o._keyword(" else")
			self.o._add(" {")
			self.o._new_line()
			self.visit(br.dump, tab+1)

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
			self.o._add(" (1) {")
		self.o._new_line()
		self.visit(node.branch, tab+1)
		self.o._tabs(tab)
		self.o._add("}")
		self.o._new_line()

	@visitor(Ast_Comment, int)
	def visit(self, node, tab):
		pass #print( "Comment")

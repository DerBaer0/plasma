from plasma.lib.visitors.visitor import *
from plasma.lib.ast import *
from plasma.lib.ops import *
from plasma.lib.utils import unsigned
from plasma.lib.fileformat.binary import T_BIN_RAW
from plasma.lib.memory import (MEM_CODE, MEM_UNK, MEM_FUNC, MEM_BYTE, MEM_WORD, MEM_DWORD, MEM_QWORD, MEM_ASCII, MEM_OFFSET)

from capstone.x86 import *

class FindArgsVisitor:
	def __init__(self, ctx=None):
		self.ctx = ctx
		self.argRegs = [X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX, X86_REG_R8, X86_REG_R9]
		self.usage = {X86_REG_RDI: "unknown", X86_REG_RSI: "unknown", X86_REG_RDX: "unknown", X86_REG_RCX: "unknown", X86_REG_R8: "unknown", X86_REG_R9: "unknown"}
		self.types = {X86_REG_RDI: "unknown", X86_REG_RSI: "unknown", X86_REG_RDX: "unknown", X86_REG_RCX: "unknown", X86_REG_R8: "unknown", X86_REG_R9: "unknown"}
		self.firstInsn = {X86_REG_RDI: None, X86_REG_RSI: None, X86_REG_RDX: None, X86_REG_RCX: None, X86_REG_R8: None, X86_REG_R9: None}
		self.REG_GROUPS = {
			X86_REG_RDI: [-1, -1, X86_REG_EDI, X86_REG_RDI],
			X86_REG_RSI: [-1, -1, X86_REG_ESI, X86_REG_RSI],
			X86_REG_RDX: [X86_REG_DL, X86_REG_DX, X86_REG_EDX, X86_REG_RDX],
			X86_REG_RCX: [X86_REG_CL, X86_REG_CX, X86_REG_ECX, X86_REG_RCX],
			X86_REG_R8: [-1, -1, -1, X86_REG_R8],
			X86_REG_R9: [-1, -1, -1, X86_REG_R9]
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
		self.functions = {
			"fak": 1,
			"ack": 2,
			"fprintf": 3,
			"strcmp": 2,
			"fwrite": 4,
			"write": 3,
			"puts": 1,
			"scanf": 2,
			"printf": 2,
			"fgets": 3
		}
		self.use = {
				# (op0, op1, op2)
				# 0 := nothing
				# 1 := read
				# 2 := write
				# 3 := read/write
				X86_INS_MOV: (2, 1, 0)
			}

	@visitor(Ast_CodeBlock)
	def visit(self, node):
		# find arguments of this function
		for ic in node.icodes: # for each instruction
			if ic.insn.id in self.use:
				for opi in range(len(ic.insn.operands)): # loop all operands
					op = ic.insn.operands[opi]
					if op.type == X86_OP_REG:
						if op.reg in self.BIGS and self.BIGS[op.reg] in self.usage and self.usage[self.BIGS[op.reg]] == "unknown":
							if self.use[ic.insn.id][opi] & 0x1:
								self.usage[self.BIGS[op.reg]] = "param"
								self.types[self.BIGS[op.reg]] = str(8 * 2**self.REG_GROUPS[self.BIGS[op.reg]].index(op.reg))
								self.firstInsn[self.BIGS[op.reg]] = ic
							elif self.use[ic.insn.id][opi] & 0x2:
								self.usage[self.BIGS[op.reg]] = "local"

		# generate high level code strings
		curValues = {
			X86_REG_RAX: UnknownOp(),
			X86_REG_RBX: UnknownOp(),
			X86_REG_RCX: UnknownOp(),
			X86_REG_RDX: UnknownOp(),
			X86_REG_RDI: UnknownOp(),
			X86_REG_RSI: UnknownOp(),
			X86_REG_R8: UnknownOp(),
			X86_REG_R9: UnknownOp()
		}

		# arguments inside a call
		for ic in node.icodes:
			if isinstance(ic, ICALL):
				funcName = self.ctx.gctx.api.get_symbol(ic.insn.operands[0].value.imm)
				numArgs = self.functions[funcName]
				ic.numArgs = numArgs

		for ic in node.icodes:
			curValues = curValues.copy()
			ic.highLevel = curValues
			if isinstance(ic, IMUL):
				reg0 = self.BIGS[ic.insn.operands[0].reg]
				rightSide = self._getRValue(ic, ic.insn.operands[1])
				ic.highLevel[reg0] = StrOp(ic.highLevel[reg0] + "*" + rightSide)
			elif isinstance(ic, IMOV):
				rightSide = self._getRValue(ic, ic.insn.operands[1])
				self._setLValue(ic, ic.insn.operands[0], rightSide)
			elif isinstance(ic, IARITH):
				rightSide = ArithExpr(self._getRValue(ic, ic.insn.operands[0]), str(ic.typ), self._getRValue(ic, ic.insn.operands[1]))
				self._setLValue(ic, ic.insn.operands[0], rightSide)
			elif isinstance(ic, ILEA):
				rightSide = self._getRValue(ic, ic.insn.operands[1])
				self._setLValue(ic, ic.insn.operands[0], rightSide)
			elif isinstance(ic, ICALL):
				reg0 = X86_REG_RAX
				#rightSide = CallExpr(self.ctx.gctx.api.get_symbol(ic.insn.operands[0].value.imm), [ic.highLevel[self.argRegs[a]] for a in range(ic.numArgs)])
				r = RegOp(reg0)
				ic.highLevel[reg0] = r
				ic.retArg = r
				# invalidate caller-safe register
				ic.highLevel[X86_REG_RCX] = UnknownOp()
				ic.highLevel[X86_REG_RDX] = UnknownOp()

	def _setLValue(self, ic, op, value):
		if op.type == X86_OP_REG:
			ic.highLevel[self.BIGS[op.reg]] = value
		elif op.type == X86_OP_MEM:
			name = "_" + chr(ord('a') + (-op.mem.disp // 4) - 1)
			ic.highLevel[name] = StrOp(value)
		else:
			# TODO error handling
			pass

	def _getIMMString(self, imm, op_size, hexa, section=None, print_data=True, force_dont_print_data=False):
		hexa = True
		imm = unsigned(imm)
		label_printed = "LL" #self._label(imm, print_colon=False)

		res = ""
		if label_printed:
			ty = self.ctx.gctx.dis.mem.get_type(imm)
			# ty == -1 : from the terminal (with -x) there are no xrefs if
			# the file was loaded without a database.
			if imm in self.ctx.gctx.dis.xrefs and ty != MEM_UNK and \
					ty != MEM_ASCII or ty == -1:
				return StrOp(str(imm))

			if ty == MEM_ASCII:
				print_data = True
				force_dont_print_data = False

		if section is None:
			section = self.ctx.gctx.dis.binary.get_section(imm)

		if section is not None and section.start == 0:
			section = None

		# For a raw file, if the raw base is 0 the immediate is considered
		# as an address only if it's in the symbols list.
		raw_base_zero = self.ctx.gctx.dis.binary.type == T_BIN_RAW and self.gctx.raw_base == 0

		if section is not None and not raw_base_zero:
			if not label_printed:
				res += "A1" #self._address(imm, print_colon=False, notprefix=True)

			if not force_dont_print_data and print_data:
				s = self.ctx.gctx.dis.binary.get_string(imm, self.ctx.gctx.max_data_size)
				if s is not None:
					res += " "
					res += '"' + s + '"'

			return StrOp(res)

		if label_printed:
			return StrOp(res)

		if op_size == 1:
			self._string("'%s'" % get_char(imm))
		elif hexa:
			self._add(hex(imm))
		else:
			if op_size == 4:
				self._add(str(c_int(imm).value))
			elif op_size == 2:
				self._add(str(c_short(imm).value))
			else:
				self._add(str(c_long(imm).value))

			if imm > 0:
				if op_size == 4:
					packed = struct.pack("<L", imm)
				elif op_size == 8:
					packed = struct.pack("<Q", imm)
				else:
					return StrOp(res)
				if set(packed).issubset(BYTES_PRINTABLE_SET):
					self._string(" \"" + "".join(map(chr, packed)) + "\"")

		return StrOp(res)

	def _getRValue(self, ic, op):

		def inv(n):
			return n == X86_OP_INVALID

		if op.type == X86_OP_REG:
			return ic.highLevel[self.BIGS[op.reg]]
		elif op.type == X86_OP_MEM:
			# FIXME: hardcoded stuff
			show_deref = False
			mm = op.mem
			res = ""
			if inv(mm.segment) and inv(mm.index) and mm.disp != 0:
				if (mm.base == X86_REG_RBP or mm.base == X86_REG_EBP): # and self.var_name_exists(i, num_op):
					# TODO ask dissassembler for given name (get_var_name)
					if ic.insn.id == X86_INS_LEA:
						res += "&("
					res += "_" + chr(ord('a') + (-op.mem.disp // 4) - 1)

					if ic.insn.id == X86_INS_LEA:
						res += ")"
					return VarOp(res)

				elif mm.base == X86_REG_RIP or mm.base == X86_REG_EIP:
					ad = ic.insn.address + ic.insn.size + mm.disp

					# FIXME einkommentiern
					if ic.insn.id != X86_INS_LEA: # and self.deref_if_offset(ad):
						return VarOp(res)

					if show_deref:
						res += "*("
					res += str(ad)
#					self._imm(ad, 4, True, force_dont_print_data=force_dont_print_data)
					if show_deref:
						res += ")"
					return StrOp(res)

				elif inv(mm.base):
					if ic.insn.id != X86_INS_LEA and self.deref_if_offset(mm.disp):
						return StrOp(res)

			printed = False

			if not inv(mm.base):
				res = StrOp(res, ic.highLevel[self.BIGS[mm.base]])
				printed = True

			elif not inv(mm.segment):
				res += "%s" % ic.highLevel[self.BIGS[mm.segment]]
				printed = True

			if not inv(mm.index):
				if printed:
					res += " + "
				if mm.scale == 1:
					res += "%s" % ic.insn.reg_name(mm.index)
				else:
					res += "(%s*%d)" % (ic.insn.reg_name(mm.index), mm.scale)
					printed = True

			if mm.disp != 0:
				section = self.ctx.gctx.dis.binary.get_section(mm.disp)
				is_label = mm.disp in self.ctx.gctx.dis.binary.reverse_symbols or mm.disp in self.ctx.gctx.dis.xrefs #self.is_label(mm.disp)

				if True: #is_label or section is not None:
					if isinstance(res, str):
						print(res + " is str op")
						res = StrOp(res)
					if mm.disp < 0:
						res = ArithExpr(res, "-", StrOp(str(-mm.disp)))
					else:
						res = ArithExpr(res, "+", StrOp(str(mm.disp)))

			if show_deref:
				return StrOp("*(", StrOp(res, ")"))
					# TODO ask dissassembler for given name (get_var_name)
#					name = "var_%x" % (-op.mem.disp)
#					if name in ic.highLevel:
#						return ic.highLevel[name]
#					else:
#						return name
			if isinstance(res, str):
				return StrOp(res)
			else:
				return res
		elif op.type == X86_OP_IMM:
			return self._getIMMString(op.value.imm, 0, True)
			# TODO: better heuristic
#			if op.imm > 0x100:
#				return hex(op.imm)
#			else:
#				return str(op.imm)
		else:
			return StrOp("U") # unknown source

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
			  len(br.nodes[0]) == 1 and self.ctx.gctx.libarch.utils.is_cmp(br.nodes[0][0]) and \
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

from capstone.x86 import *

class UnknownOp():
	def __init__(self):
		pass

	def __str__(self):
		return "?"

	def writeOut(self, o):
		o._add("?")

class NoneOp():
	def __init__(self):
		pass

	def __str__(self):
		return ""

	def writeOut(self, o):
		pass

class TextOp():
	def __init__(self, str1, str2=None):
		self.str1 = str1
		if str2 == None:
			self.str2 = NoneOp()
		else:
			self.str2 = str2

	def __str__(self):
		return str(self.str1) + str(self.str2)

	def writeOut(self, o):
		if isinstance(self.str1, str):
			o._add(self.str1)
		else:
			self.str1.writeOut(o)
		if isinstance(self.str2, str):
			o._add(self.str2)
		else:
			self.str2.writeOut(o)

class StrOp():
	def __init__(self, str):
		self.str = str

	def __str__(self):
		return "\"" + self.str + "\""

	def writeOut(self, o):
		o._string("\"" + self.str + "\"")

class VarOp():
	def __init__(self, str):
		self.str = str

	def __str__(self):
		return self.str

	def writeOut(self, o):
		o._variable(self.str)

class ArithExpr():
	def __init__(self, left, op, right):
		self.left = left
		self.op = op
		self.right = right

	def __str__(self):
		return str(self.left) + " " + str(self.op) + " " + str(self.right)

	def writeOut(self, o):
		self.left.writeOut(o)
		o._add(" " + self.op + " ")
		self.right.writeOut(o)

class CallExpr():
	def __init__(self, func, args):
		self.func = func
		self.args = args

	def __str__(self):
		res = self.func + "("
		if len(self.args) > 0:
			res += str(self.args[0])
			for i in range(1, len(self.args)):
				res += ", " + str(self.args[i])
		return res

	def writeOut(self, o):
		o._retcall(self.func)
		o._add("(")
		if len(self.args) > 0:
			self.args[0].writeOut(o)
			for i in range(1, len(self.args)):
				o._add(", ")
				self.args[i].writeOut(o)
		o._add(")")

class RegOp():
	counter = 0

	def __init__(self, reg):
		self.reg = reg
		self.num = RegOp.counter
		RegOp.counter += 1
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

	def __str__(self):
		return "%" + chr(ord('A') +  self.num)
#		return "%" + self.regName[self.reg]

	def writeOut(self, o):
		o._add("%" + chr(ord('A') +  self.num))

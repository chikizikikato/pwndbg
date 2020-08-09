# -*- coding: utf-8 -*-


from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals



import gdb
import re


class GDBVariableAPI():
	@staticmethod
	def set_address(var_name, addr):
		gdb.execute("set var ${0}={1}".format(str(var_name), hex(addr)))
		
	@staticmethod
	def get_address(var_name):
		try:
			o = gdb.execute("p ${0}".format(str(var_name)), to_string=True)
		except gdb.error:
			return False
		m = re.match(".*?=.*?[0-9]", o)
		if(m is None):
			return False
		return int(o[m.span()[1]-1:])

#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb
import re

import pwndbg.memory
import pwndbg.proc
import pwndbg.elf
import pwndbg.chain
import pwndbg.commands
import pwndbg.emu.emulator
import pwndbg.symbol
import pwndbg.arch
import pwndbg.abi
import pwndbg.chain
import pwndbg.commands.pie
import pwndbg.gdbutils.vars
import pwndbg.vmmap
from pwndbg.color import message






class PIEHandler():
	def __init__(self):
		pass
		 
	def get_symbol(self):
		print(message.notice("Executable is a PIE, so we can only give exact offsets"))
		self.main_symbol = pwndbg.symbol.SymbolFactory("main").create_symbol()
		return self.main_symbol
		
	
class EXEHandler():
	def __init__(self):
		self.main_symbol = pwndbg.symbol.SymbolFactory("main").create_symbol()
		
	def get_symbol(self):
		if(not self.main_symbol.best_addr or pwndbg.vmmap.check_aslr()):
			print(message.notice("Emulating __libc_start_main call..."))
			self._emulate_main_addr()
		return self.main_symbol

	def _emulate_main_addr(self):
		start_address = self._get_start_address()
		main_addr = pwndbg.emu.emulator.FunctionArgumentGetter(start_address, "__libc_start_main", 0, alternative_index_call=2).get_argument_of_target_function() # when aslr->could not get address. only when aslr on not working -> unmapped memory fetch
		if(main_addr is not None):
			self.main_symbol = pwndbg.symbol.Symbol.from_whole_address(main_addr, "main")
			pwndbg.gdbutils.vars.GDBVariableAPI.set_address("main", main_addr)
		else:
			print(message.error("main address could not be resolved!"))
		
	def _get_start_address(self):
		start_symbols = pwndbg.symbol.FunctionAddressFinder("start", extra_prefixes=['_', '__']).find_addresses()
		return (start_symbols[0] if(len(start_symbols)>0) else int((pwndbg.elf.entry() or pwndbg.elf.get_entry_point_addr_local())))
		
# MAybe class AliveHandler
		
class FileHandlerFactory():
	@staticmethod
	def get_handler():
		pie_checker = pwndbg.commands.pie.PIEChecker()
		if(not pie_checker.is_pie() or pwndbg.proc.alive):
			return EXEHandler()
		else:
			return PIEHandler()

@pwndbg.commands.ArgparsedCommand("print address of 'main' function")
@pwndbg.commands.OnlyWithFile
def mainaddr():
	file_handler = FileHandlerFactory.get_handler()
	main_symbol = file_handler.get_symbol()
	main_symbol.print_symbol()

@pwndbg.commands.ArgparsedCommand("sets breakpoint at start of 'main' function")
@pwndbg.commands.OnlyWithFile
def bmain():
	file_handler = FileHandlerFactory.get_handler()
	main_symbol = file_handler.get_symbol()
	breakpoint_addr = main_symbol.best_addr
	if(not isinstance(breakpoint_addr, pwndbg.symbol.Address)):
		print(message.error("Could not find absolute address to break on"))
		return
	gdb.Breakpoint("*{0}".format(hex(int(breakpoint_addr))), temporary=True)


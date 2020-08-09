#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Compatibility functionality for GDBINIT users.

https://github.com/gdbinit/Gdbinit/blob/master/gdbinit
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb

import pwndbg.commands
import pwndbg.elf
from  pwndbg.color import message

@pwndbg.commands.ArgparsedCommand("GDBINIT compatibility alias for 'start' command.")
def init():
    """GDBINIT compatibility alias for 'start' command."""
    pwndbg.commands.start.start()

@pwndbg.commands.ArgparsedCommand("GDBINIT compatibility alias for 'tbreak __libc_start_main; run' command.")
def sstart():
    """GDBINIT compatibility alias for 'tbreak __libc_start_main; run' command."""
    gdb.execute('tbreak __libc_start_main')
    gdb.execute('run')

@pwndbg.commands.ArgparsedCommand("GDBINIT compatibility alias for 'main' command.")
def main():
    """GDBINIT compatibility alias for 'main' command."""
    pwndbg.commands.start.start()

@pwndbg.commands.ArgparsedCommand("GDBINIT compatibility alias for 'libs' command.")
@pwndbg.commands.OnlyWhenRunning
def libs():
    """GDBINIT compatibility alias for 'libs' command."""
    pwndbg.commands.vmmap.vmmap()

@pwndbg.commands.ArgparsedCommand("GDBINIT compatibility alias to print the entry point. See also the 'entry' command.")
def entry_point():
    """GDBINIT compatibility alias to print the entry point.
    See also the 'entry' command."""
    entry = pwndbg.elf.entry() or pwndbg.elf.get_entry_point_addr_local()
    if(entry is not None):
        print(hex(int(entry)))
    else:
        print(message.error("Could not resolve entry point"))

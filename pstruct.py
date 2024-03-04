"""
Module Name: pstruct.py
Author: imLZH1
Date: March 3, 2024
"""
from __future__ import annotations

import argparse
import ctypes
import pwndbg.chain
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.enhance
import pwndbg.gdblib.file
import pwndbg.gdblib.shellcode
import pwndbg.lib.memory
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
         formatter_class=argparse.RawTextHelpFormatter,
        description="Usage: show_hex <address> <structName>",
)
# The parameter 'structName' may be developed in the future
parser.add_argument(
        'addr',
        help="Address hint to be given to pstruct.",
        type=pwndbg.commands.sloppy_gdb_parse
)

parser.add_argument(
        'StructName',
        help="Not get StructName",
        type=str,
        nargs='?',
        default="def_name"
        )

class _IO_FILE(ctypes.Structure):
    _fields_ = [
        ("_flags", ctypes.c_uint),
        ("_IO_read_ptr", ctypes.c_longlong),
        ("_IO_read_end", ctypes.c_longlong),
        ("_IO_read_base", ctypes.c_longlong),
        ("_IO_write_base", ctypes.c_longlong),
        ("_IO_write_ptr", ctypes.c_longlong),
        ("_IO_write_end", ctypes.c_longlong),
        ("_IO_buf_base", ctypes.c_longlong),
        ("_IO_buf_end", ctypes.c_longlong),
        ("_IO_save_base", ctypes.c_longlong),
        ("_IO_backup_base", ctypes.c_longlong),
        ("_IO_save_end", ctypes.c_longlong),
        ("_markers", ctypes.c_longlong),
        ("_chain", ctypes.c_longlong),
        ("_fileno", ctypes.c_int),
        ("_flags2", ctypes.c_int),
        ("_old_offset", ctypes.c_ulonglong),
        ("_cur_column", ctypes.c_ushort),
        ("_vtable_offset", ctypes.c_byte),
        ("_shortbuf", ctypes.c_byte),
        ("_lock", ctypes.c_longlong),
        ("_offset", ctypes.c_ulonglong),
        ("_codecvt", ctypes.c_longlong),
        ("_wide_data", ctypes.c_longlong),
        ("_freeres_list", ctypes.c_longlong),
        ("_freeres_buf", ctypes.c_longlong),
        ("__pad5", ctypes.c_size_t),
        ("_mode", ctypes.c_int),
        ("_unused2", ctypes.c_char * (15 * ctypes.sizeof(ctypes.c_int) - 4 * ctypes.sizeof(ctypes.c_void_p) - ctypes.sizeof(ctypes.c_size_t))),
    ]
    #def __repr__(self):
    #    #fps = [f"{name} = {hex(getattr(self, name))}" for name, _ in self._fields_]
    #    fps = [f"\033[94m{name}\033[0m = \033[96m{hex(getattr(self, name))}\033[0m" for name, _ in self._fields_]
    #    return "{\n    " + ", \n    ".join(fps) + "\n  }"
    def __repr__(self):
        fps = []
        for name, field_type in self._fields_:
            value = getattr(self, name)
            if name == "_unused2":
                # Treat _unused2 as a byte array and convert it to a hexadecimal string
                v = '\'\\x00\''
                fps.append(f"\033[94m{name}\033[0m = \033[96m{v}\033[0m <fill 0x14>")
            else:
                symbol_info = pwndbg.chain.format(value,1)
                if '...' in symbol_info:
                    symbol_info = symbol_info.split(' ')
                    symbol_info = ''.join(symbol_info[:-2])
                    pass
                if(symbol_info!='0x0'):
                    fps.append(f"\033[94m{name}\033[0m = \033[96m{hex(value)}\033[0m  <{symbol_info}\033[0m>")
                else:
                    fps.append(f"\033[94m{name}\033[0m = \033[96m{hex(value)}\033[0m")
        return "{\n    " + ", \n    ".join(fps) + "\n  }"


class _IO_FILE_plus(ctypes.Structure):
    _fields_ = [
        ("_file", _IO_FILE),
        ("vtable", ctypes.c_longlong)  # 指向 _IO_jump_t 结构体的指针
    ]
    def __repr__(self):
        #fps = [f"\033[91m{name}\033[0m = {getattr(self, name)}" for name, _ in self._fields_]
        #return "$1 = {\n  " + ", \n  ".join(fps) + "\n}

        symbol_info = pwndbg.chain.format(self.vtable)
        #fps.append(f"\033[94m{name}\033[0m = \033[96m{hex(value)}\033[0m  <{symbol_info}\033[0m>")

        d  = '$1 = {'
        d += f"\n\033[94m$_FILE\033[0m = {self._file},\n\033[94mvtable\033[0m = \033[96m{hex(self.vtable)}\033[0m <{symbol_info}\033[0m>\n"
        d += '}'
        return d

@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def pstruct(addr,StructName='def_name') -> None:
    data = pwndbg.gdblib.memory.read(addr, 0xe0, partial=True)
    data = bytes(data)
    fp = _IO_FILE_plus.from_buffer_copy(data)
    print(f'\033[93m$addr\033[0m = \033[92m{hex(addr)}\033[0m')
    print(fp)

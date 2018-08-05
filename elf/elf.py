import sys

from ctypes import *
from pycca.asm import *

from struct import unpack, pack
from typing import NewType, List, Union, Any
from dataclasses import dataclass, fields
from itertools import chain



# ELF basic type definition.

Elf64_Addr      = c_uint64
Elf64_Off       = c_uint64
Elf64_Byte      = c_uint8
Elf64_Half      = c_uint16
Elf64_Sword     = c_int32
Elf64_Word      = c_uint32
Elf64_Sxword    = c_int64
Elf64_Xword     = c_uint64

_char16         = NewType('_char16', c_uint8)


struct_fmt = {
    c_int8:   'b',
    c_uint8:  'B',
    c_int16:  'h',
    c_uint16: 'H',
    c_int32:  'i',
    c_uint32: 'I',
    c_int64:  'q',
    c_uint64: 'Q',

    _char16:  '16s'
}


struct_sz = {
    c_int8:   1,
    c_uint8:  1,
    c_int16:  2,
    c_uint16: 2,
    c_int32:  4,
    c_uint32: 4,
    c_int64:  8,
    c_uint64: 8,

    _char16:  16
}


ET_NONE     = 0
ET_REL      = 1
ET_EXEC     = 2
ET_DYN      = 3
ET_CORE     = 4


@dataclass
class Elf64_Hdr:
    ident:      _char16
    type:       c_uint16
    machine:    c_uint16
    version:    c_uint32
    entry:      Elf64_Addr
    phoff:      Elf64_Off
    shoff:      Elf64_Off
    flags:      c_uint32
    ehsize:     c_uint16
    phentsize:  c_uint16
    phnum:      c_uint16
    shentsize:  c_uint16
    shnum:      c_uint16
    shstrndx:   c_uint16


@dataclass
class Elf64_Shdr:
    name:       c_uint32
    type:       c_uint32
    flags:      c_uint64
    addr:       Elf64_Addr
    offset:     Elf64_Off
    size:       c_uint64
    link:       c_uint32
    info:       c_uint32
    addralign:  c_uint64
    entsize:    c_uint64


@dataclass
class Elf64_Sym:
    name:       Elf64_Word
    info:       c_uint8
    other:      c_uint8
    shndx:      Elf64_Half
    value:      Elf64_Addr
    size:       Elf64_Xword


R_x86_64_NONE      = 0   # None
R_x86_64_64        = 1   # S + A
R_x86_64_PC32      = 2   # S + A - P
R_x86_64_GOT32     = 3   # G + A
R_x86_64_PLT32     = 4   # L + A - P
R_x86_64_COPY      = 5   # Value is copied directly from shared objuect
R_x86_64_GLOB_DAT  = 6   # S
R_x86_64_JUMP_SLOT = 7   # S
R_x86_64_RELATIVE  = 8   # B + A
R_x86_64_GOTPCREL  = 9   # G + GOT + A - P
R_x86_64_32        = 10  # S + A
R_x86_64_32S       = 11  # S + A
R_x86_64_16        = 12  # S + A
R_x86_64_PC16      = 13  # S + A - P
R_x86_64_8         = 14  # S + A
R_x86_64_PC8       = 15  # S + A - P
R_x86_64_PC64      = 24  # S + A - P
R_x86_64_GOTOFF64  = 25  # S + A - GOT
R_x86_64_GOTPC32   = 26  # GOT + A - P
R_x86_64_SIZE32    = 32  # Z + A
R_x86_64_SIZE64    = 33  # Z + A


def ELF64_R_SYM(i): return i >> 32
def ELF64_R_TYPE(i): return Elf64_Word(i).value
def ELF64_R_INFO(s, t): return Elf64_Xword(s << 32 | t)


@dataclass
class Elf64_Rela:
    offset:     Elf64_Addr
    info:       c_uint64
    addend:     c_int64


PT_NULL         = 0
PT_LOAD         = 1
PT_DYNAMIC      = 2
PT_INTERP       = 3
PT_NOTE         = 4
PT_SHLIB        = 5
PT_PHDR         = 6

PF_X            = 0x1
PF_W            = 0x2
PF_R            = 0x4
PF_MASKPROC     = 0xf0000000


@dataclass
class Elf64_Phdr:
    type:       Elf64_Word
    flags:      Elf64_Word
    offset:     Elf64_Off
    vaddr:      Elf64_Addr
    paddr:      Elf64_Addr
    filesz:     Elf64_Xword
    memsz:      Elf64_Xword
    align:      Elf64_Xword


DT_NULL         = 0
DT_NEEDED       = 1
DT_PLTRELSZ     = 2
DT_PLTGOT       = 3
DT_HASH         = 4
DT_STRTAB       = 5
DT_SYMTAB       = 6
DT_RELA         = 7
DT_RELASZ       = 8
DT_RELAENT      = 9
DT_STRSZ        = 10
DT_SYMENT       = 11
DT_INIT         = 12
DT_FINI         = 13
DT_SONAME       = 14
DT_RPATH        = 15
DT_SYMBOLIC     = 16
DT_REL          = 17
DT_RELSZ        = 18
DT_RELENT       = 19
DT_PLTREL       = 20
DT_DEBUG        = 21
DT_TEXTREL      = 22
DT_IMPREL       = 23
DT_BIND_NOW     = 24
DT_RUNPATH      = 25

@dataclass
class Elf64_Dyn:
    d_tag:      Elf64_Sword
    d_un:       Elf64_Addr


# ----------------------------- Misc ----------------------------- #


def __read_struct(f, t, offset=0):
    if offset != 0:
        f.seek(offset)

    return t(**{field.name: unpack(struct_fmt[field.type], f.read(struct_sz[field.type]))[0]
                for field in fields(t)})


def __read_struct_array(f, t, n, offset=0):
    if offset != 0:
        f.seek(offset)

    return [t(**{field.name: unpack(struct_fmt[field.type], f.read(struct_sz[field.type]))[0]
                 for field in fields(t)}) for _ in range(n)]


def __write_struct(f, s, offset=0):
    if offset != 0:
        f.seek(offset)

    f.write(b''.join(pack(struct_fmt[field.type], s.__dict__[field.name]) for field in fields(s)))


def __write_struct_array(f, ss, offset=0):

    if offset != 0:
        f.seek(offset)

    f.write(b''.join(pack(struct_fmt[field.type], s.__dict__[field.name]) for s in ss for field in fields(s)))


def __pack_struct(s):
    return b''.join(pack(struct_fmt[field.type], s.__dict__[field.name]) for field in fields(s))


def __pack_struct_array(ss):
    return b''.join(pack(struct_fmt[field.type], s.__dict__[field.name]) for s in ss for field in fields(s))


def __struct_size(t):
    return sum(struct_sz[field.type] for field in fields(t))

# @Debug:
section_type_str = {
     0: 'NULL',
     1: 'PROGBITS',
     2: 'SYMTAB',
     3: 'STRTAB',
     4: 'RELA',
     5: 'HASH',
     6: 'DYNAMIC',
     7: 'NOTE',
     8: 'NOBITS',
     9: 'REL',
    10: 'SHLIB',
    11: 'DYNSYM',
}


def read_bytes(f, size, offset=0):
    f.seek(offset)
    return f.read(size)


def load_section(f, s):
    handler_mapping = {
        0  : lambda f, s: None,
        1  : lambda f, s: read_bytes(f, s.size, offset=s.offset),
        2  : lambda f, s: __read_struct_array(f, Elf64_Sym, s.size // s.entsize, offset=s.offset),
        3  : lambda f, s: read_bytes(f, s.size, offset=s.offset),
        4  : lambda f, s: __read_struct_array(f, Elf64_Rela, s.size // s.entsize, offset=s.offset),
        5  : lambda f, s: None,
        6  : lambda f, s: None,
        7  : lambda f, s: None,
        8  : lambda f, s: None,
        9  : lambda f, s: None,
        10 : lambda f, s: None,
        11 : lambda f, s: None,
        12 : lambda f, s: None,
        13 : lambda f, s: None,
        14 : lambda f, s: None,
    }
    f.seek(s.offset)
    return handler_mapping[s.type](f, s)


def create_start_function():
    # @Note: Set <_start+0x1d> to right offset to <main> function.
    return (b'\x31\xed' +
            b'\x49\x89\xd1' +
            b'\x5e' +
            b'\x48\x89\xe2' +
            b'\x48\x83\xe4\xf0' +
            b'\x50' +
            b'\x54' +
            b'\x4c\x8d\x05\x9a\x01\x00\x00' +
            b'\x48\x8d\x0d\x23\x01\x00\x00' +
            b'\x48\x8d\x3d\x00\x00\x00\x00' +
            b'\xff\x15\x66\x0a\x20\x00' +
            b'\xf4' +
            b'\x0f\x1f\x44\x00\x00')


def create_initial_plt_entry(got_rel):
    p1 = pack('i', got_rel + 0x8)
    p2 = pack('i', got_rel + 0x10)
    return b'\xff\x35' + p1 + b'\xff\x25' + p2 + b'\x0f\x1f\x40\x00'


def create_plt_entry(got_off, index, sec_off):
    p1 = pack('i', got_off)
    p2 = pack('i', index)
    p3 = pack('i', sec_off)
    return b'\xff\x25' + p1 + b'\x68' + p2 + b'\xe9' + p3


def run_linking(fins, fout, libs=None):
    """
    Output file layout:
      +---------+ --- 0x0
      | Hdr     |
      +---------+ --- 0x40
      | Phdr    |     # contains 10 entries as a maximum.
      +---------+ --- 0x40 + <rest N> * 64
      | .interp |
      +---------+
      | Dynamic |
      +---------+
      | Rela    |
      +---------+
      | PLT     |
      +---------+
      | .text   |
      +---------+
      | .rodata |
      +---------+
      | GDT     |
      +---------+
      | .data   |
      +---------+
      | .bss    |
      +---------+

    Algorithm:
      1. Read Hdr, Shdr from all input files.
      2.
    """

    if libs is None:
        libs = []

    @dataclass
    class OutSection:
        # type:       Elf64_Word
        # flags:      Elf64_Xword
        # align:      Elf64_Xword
        needed:     bool       = False
        addr:       Elf64_Addr = None
        offset:     Elf64_Off  = 0
        entsize:    c_uint64   = 0
        data:       bytes      = b''

        def __post_init__(self):
            self._size = len(self.data)

        size = property(lambda self: self._size)

        def commit(self):
            self._size = len(self.data)

    class FixedOutSection(OutSection):
        def __init__(self, size, *args, **kwargs):
            super().__init__(self, *args, **kwargs)
            self._size = size

        def commit(self): pass

    class NobitsOutSection(OutSection):
        @OutSection.size.setter
        def size(self, value):
            self._size = value


    ehdr_offset     = 0
    ehdr_size       = __struct_size(Elf64_Hdr)
    phdr_offset     = ehdr_offset + ehdr_size
    phdr_entsize    = __struct_size(Elf64_Hdr)
    phdr_size       = 10 * phdr_entsize
    sections_offset = phdr_offset + phdr_size

    res_sections = {
        # r-x
        b'.plt'     : OutSection(),
        b'.text'    : OutSection(data=bytearray(create_start_function())),

        # r--
        b'.interp'  : OutSection(data=b'lib64/ld-linux-x86-64.so.2\0'),
        b'.rela'    : OutSection(entsize=__struct_size(Elf64_Rela)),
        b'.rela.plt': OutSection(entsize=__struct_size(Elf64_Rela)),
        b'.strtab'  : OutSection(),
        b'.symtab'  : OutSection(entsize=8),
        b'.rodata'  : OutSection(),

        # rw-
        b'.dynamic' : FixedOutSection(size=(len(libs) + 50) * __struct_size(Elf64_Dyn), entsize=__struct_size(Elf64_Dyn)),
        b'.got'     : OutSection(entsize=8),
        b'.got.plt' : OutSection(entsize=8),
        b'.data'    : OutSection(data=bytearray()),
        b'.bss'     : NobitsOutSection(),
    }

    rx_section_names = (b'.plt', b'.text')
    r_section_names  = (b'.interp', b'.rela', b'.rela.plt', b'.rodata')
    rw_section_names = (b'.dynamic', b'.got', b'.got.plt', b'.data', b'.bss')

    def va(sname):
        if sname in rx_section_names:
            return 0x0
        elif sname in r_section_names:
            return 0x200000
        elif sname in rw_section_names:
            return 0x250000

    for f in fins:
        elf_hdr = __read_struct(f, Elf64_Hdr)
        shdrs = __read_struct_array(f, Elf64_Shdr, elf_hdr.shnum, offset=elf_hdr.shoff)

        # for item in vars(elf_hdr).items():
        #     print('%15s => %s' % item)
        # for item in shdrs:
        #     print(item)
        # sys.stdout.flush()

        # assert elf_hdr.ident[:4] == b'\x7fELF', \
        #     f"File '{name}' doesn't contain ELF magic."
        # assert elf_hdr.shentsize == 64

        sections = [load_section(f, s) for s in shdrs]

        # @Thought: Split progbits appending and other to two separate loops.
        # That must be a more careful implementation for lazy-formed object files,
        # which have several sections with the same name.

        # @Issue: Auto-initialization for specified section name.

        strtab = sections[elf_hdr.shstrndx]
        symtab = next(y for x, y in zip(shdrs, sections) if x.type == 2)
        for s, data in zip(shdrs, sections):
            section_name = create_string_buffer(strtab[s.name:]).value

            if section_name not in res_sections:
                print(section_name)
                continue

            if s.type == 1:  # PROGBITS
                res_sections[section_name].data += data  # Acumulate corresponding section data.
            elif s.type == 2:  # SYMTAB
                for sym in data:
                    symbol_name = create_string_buffer(sections[s.link][sym.name:]).value
                    if symbol_name == 'main':
                        # TODO: Mark <main> function presence.
                        res_sections[b'.text'].data[0x1d:0x12] = bytearray(pack('i', res_sections[b'.text'].size + sym.value - 0x1d))

                    if sym.shndx >= len(shdrs): continue

                    ref_section_name = create_string_buffer(strtab[shdrs[sym.shndx].name:]).value
                    if ref_section_name not in res_sections: continue

                    res_sections[section_name].data += __pack_struct(Elf64_Sym(
                        name = res_sections[b'.strtab'].size + sym.name,  # @Note: In this line of code I make assumptions that corresponding '.strtab' section goes first in section list of current file.
                        value = res_sections[create_string_buffer(strtab[shdrs[sym.shndx].name:]).value].size + sym.value,
                        size = sym.size,
                        info = sym.info,
                        other = sym.other,
                        shndx = 0  # It doesn't matter now.
                    ))  # TODO: Error: out of range.
            elif s.type == 3:  # STRTAB
                res_sections[section_name].data += data
            elif s.type == 4:  # RELA
                ref_section_name = create_string_buffer(strtab[shdrs[s.info].name:]).value # Name of section to which the relcoation applies.
                for r in data:
                    print(ELF64_R_SYM(r.info))
                    if ELF64_R_TYPE(r.info) ==  R_x86_64_NONE:
                        pass
                    elif ELF64_R_TYPE(r.info) == R_x86_64_64:
                        pass
                        # res_sections[section_name].data += __pack_struct(Elf64_Rela(
                        #     offset = res_sections[ref_section_name].offset + res_sections[ref_section_name].last_size + r.offset # TODO: Implement offset computation.,
                        #     info = ELF64_R_INFO(XXX, ELF64_R_TYPE(r.info)),
                        #     addend = r.addend
                        # ))
                    elif ELF64_R_TYPE(r.info) == R_x86_64_PC32:
                        S = symtab[ELF64_R_SYM(r.info)].value
                        A = r.addend
                        P = res_sections[ref_section_name].size + r.offset
                        offset = res_sections[ref_section_name].size + r.offset
                        res_sections[ref_section_name].data[offset:offset+4] = pack(struct_fmt[c_int32], S + A - P)
                    elif ELF64_R_TYPE(r.info) == R_x86_64_PLT32:
                        if not res_sections[b'.got.plt'].needed:
                            res_sections[b'.got.plt'].needed = True

                        if not res_sections[b'.plt'].needed:
                            res_sections[b'.plt'].needed = True
                            # TODO: Replace section type codes by corresponding constants.
                            # TODO: Sep appropriate align value for .plt sections.
                            res_sections[b'.plt'].data = create_initial_plt_entry(res_sections[b'.got.plt'].offset)

                        res_sections[b'.plt'].data += create_plt_entry(
                                (res_sections[b'.got.plt'].offset + res_sections[b'.got.plt'].size) - (res_sections[b'.plt'].offset + res_sections[b'.plt'].size),
                                res_sections[b'.got.plt'].size // 8,
                                -(res_sections[b'.plt'].size + 0x10)
                        )
                        res_sections[b'.got.plt'].data += pack('I', res_sections[b'.plt'].offset + res_sections[b'.plt'].size)

                        L = res_sections[b'.plt'].offset + res_sections[b'.plt'].size
                        A = r.addend
                        P = res_sections[ref_section_name].size + r.offset
                        offset = res_sections[ref_section_name].size + r.offset
                        res_sections[ref_section_name].data[offset:offset+4] = pack(struct_fmt[c_int32], L + A - P)
            elif s.type == 8:  # NOBITS
                res_sections[section_name].size += s.size
            # elif s.type == 9  # REL
            #     pass  # TODO

        map(lambda item: item.commit(), res_sections.values())

    libstr_offsets = []
    for lpath in libs:
        libstr_offsets.append(res_sections[b'.strtab'].size)
        res_sections[b'.strtab'].data += b'%s\0' % bytes(lpath, 'utf-8')
        res_sections[b'.strtab'].commit()

    # Setting the layout.
    offset = sections_offset
    for section_name in chain(rx_section_names, r_section_names, rw_section_names):
        sec = res_sections[section_name]
        sec.offset = offset
        offset += sec.size

    rx_section_offset = min(res_sections[sname].offset for sname in rx_section_names)
    rx_section_size   = sum(res_sections[sname].size   for sname in rx_section_names)
    r_section_offset  = min(res_sections[sname].offset for sname in r_section_names)
    r_section_size    = sum(res_sections[sname].size   for sname in r_section_names)
    rw_section_offset = min(res_sections[sname].offset for sname in rw_section_names)
    rw_section_size   = sum(res_sections[sname].size   for sname in rw_section_names)
    dyn_offset        = res_sections[b'.dynamic'].offset
    dyn_size          = res_sections[b'.dynamic'].size

    # Dynamic table.
    # --------------
    res_sections[b'.dynamic'].data += __pack_struct_array(Elf64_Dyn(DT_NEEDED, off) for off in libstr_offsets)
    # res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_GNU_HASH, ))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_STRTAB, res_sections[b'.strtab'].offset))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_SYMTAB, res_sections[b'.symtab'].offset))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_STRSZ, res_sections[b'.strtab'].size))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_SYMENT, res_sections[b'.symtab'].entsize))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_PLTGOT, res_sections[b'.plt'].offset))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_PLTRELSZ, res_sections[b'.plt'].size))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_PLTREL, res_sections[b'.plt'].size))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_RELA, res_sections[b'.rela'].offset))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_RELASZ, res_sections[b'.rela'].size))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_RELAENT, res_sections[b'.rela'].entsize))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_RELAENT, res_sections[b'.rela'].entsize))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_NULL, 0))  # <--- END

    # PHDRs
    phdrs = []
    print('%#x - %#x' % (phdr_offset, phdr_size))
    phdrs.append(Elf64_Phdr(type=PT_PHDR, flags=PF_R, offset=phdr_offset, vaddr=phdr_offset, paddr=phdr_offset,
                            filesz=phdr_size, memsz=phdr_size, align=2**3))
    phdrs.append(Elf64_Phdr(type=PT_INTERP, flags=PF_R, offset=res_sections[b'.interp'].offset, vaddr=va(b'.interp'), paddr=va(b'.interp'),
                            filesz=res_sections[b'.interp'].size, memsz=res_sections[b'.interp'].size, align=2**0))
    phdrs.append(Elf64_Phdr(type=PT_LOAD, flags=PF_R | PF_X, offset=rx_section_offset, vaddr=rx_section_offset, paddr=rx_section_offset,
                            filesz=rx_section_size, memsz=rx_section_size, align=2**21))
    phdrs.append(Elf64_Phdr(type=PT_LOAD, flags=PF_R, offset=r_section_offset, vaddr=r_section_offset, paddr=r_section_offset,
                            filesz=r_section_size, memsz=r_section_size, align=2**21))
    phdrs.append(Elf64_Phdr(type=PT_LOAD, flags=PF_R | PF_W, offset=rw_section_offset, vaddr=rw_section_offset, paddr=rw_section_offset,
                            filesz=rw_section_size, memsz=rw_section_size, align=2**21))
    phdrs.append(Elf64_Phdr(type=PT_DYNAMIC, flags=PF_R | PF_W, offset=dyn_offset, vaddr=dyn_offset, paddr=dyn_offset,
                            filesz=dyn_size, memsz=dyn_size, align=2**3))

    elf_hdr.type = ET_EXEC
    elf_hdr.entry = res_sections[b'.text'].offset
    elf_hdr.phoff = phdr_offset
    elf_hdr.shoff = 0
    elf_hdr.phentsize = phdr_entsize
    elf_hdr.phnum = phdr_size // phdr_entsize
    elf_hdr.shentsize = 0
    elf_hdr.shnum = 0
    elf_hdr.shstrndx = 0

    # Writing result into file.
    __write_struct(fout, elf_hdr)
    __write_struct_array(fout, phdrs, offset=phdr_offset)
    for name in chain(rx_section_names, r_section_names, rw_section_names):
        sec = res_sections[name]
        fout.seek(sec.offset)
        fout.write(sec.data)

import sys

from ctypes import *
from pycca.asm import *

from struct import unpack, pack
from typing import NewType, List, Dict, Union, Any, ClassVar
from dataclasses import dataclass, field, fields, asdict
from itertools import chain, repeat, groupby
from functools import reduce



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


SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


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


STB_LOCAL   = 0
STB_GLOBAL  = 1
STB_WEAK    = 2

STT_NOTYPE  = 0
STT_OBJECT  = 1
STT_FUNC    = 2
STT_SECTION = 3
STT_FILE    = 4
STT_COMMON  = 5

def ELF64_ST_BIND(i): return i >> 4
def ELF64_ST_TYPE(i): return i & 0xf
def ELF64_ST_INFO(bind, type): return (bind << 4) | (type & 0xf)

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
def ELF64_R_INFO(s, t): return (s << 32) | t


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
DT_JMPREL       = 23
DT_BIND_NOW     = 24
DT_RUNPATH      = 25

@dataclass
class Elf64_Dyn:
    d_tag:      Elf64_Xword
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


def create_initial_plt_entry(got_plus_8, got_plus_16):
    p1 = pack('i', got_plus_8)
    p2 = pack('i', got_plus_16)
    return b'\xff\x35' + p1 + b'\xff\x25' + p2 + b'\x0f\x1f\x40\x00'


def create_plt_entry(got_off, index, sec_off):
    p1 = pack('i', got_off)
    p2 = pack('i', index)
    p3 = pack('i', sec_off)
    return b'\xff\x25' + p1 + b'\x68' + p2 + b'\xe9' + p3


def check_unresolved_symbols(ss):
    res = True

    for s in ss:
        if s.shndx == SHN_UNDEF:
            print("Error: unresolved symbol '%s'." % s.name)
            res = False

    return res



def run_linking(fins, fout, libs=None):
    """
    Linking algorithm:
    1. Read progbits sections, symbols and relocations.
    2. Perform symbol resolution.
    3. Decide where all the contents should go in the output file.
    4. Perform relocation.
    5. Fill dynamic table.
    6. Fill program header.
    7. Write to the output file.
    """

    @dataclass
    class Section:
        type:       int = 0
        flags:      int = 0
        offset:     int = 0
        vaddr:      int = 0
        data:       bytearray = field(default_factory=bytearray, repr=False)

        size: ClassVar = property(lambda self: len(self.data))
        estimated_size: ClassVar = property(lambda self: self.size)

    @dataclass
    class FixedSection(Section):
        def __init__(self, size, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._estimated_size = size

        estimated_size: ClassVar = property(lambda self: self._estimated_size)

    @dataclass
    class Symbol:
        name:       bytes = b''
        value:      int = 0
        size:       int = 0
        type:       int = 0
        bind:       int = 0
        sect:       bytes = None

    @dataclass
    class Rela:
        offset:     int
        symndx:     int
        type:       int
        addend:     int

    @dataclass
    class TranslationUnit:
        progbits_offset:    Dict[bytes, int] = field(default_factory=dict)
        bss_offset:         int = 0
        symbols:            List[Symbol] = field(default_factory=list)
        relas:              List[Elf64_Rela] = field(default_factory=list)


    progbits = {}
    bss_size = 0
    plt_num_entries = 0
    rela_num_entries = 0

    # Step 1: Load data.
    tus = []
    for f in fins:
        tu = TranslationUnit()
        tus.append(tu)

        ehdr = __read_struct(f, Elf64_Hdr)
        shdrs = __read_struct_array(f, Elf64_Shdr, ehdr.shnum, offset=ehdr.shoff)

        sec_strtab_shdr = shdrs[ehdr.shstrndx]
        f.seek(sec_strtab_shdr.offset)
        sec_strtab = f.read(sec_strtab_shdr.size)
        section_names = [create_string_buffer(sec_strtab[s.name:]).value for s in shdrs]

        for sname, s in progbits.items():
            tu.progbits_offset[sname] = s.size

        for s, sname in zip(shdrs, section_names):
            if s.type == 1:  # PROGBITS
                if sname not in progbits:
                    progbits[sname] = Section(type=1, flags=s.flags)
                    tu.progbits_offset[sname] = progbits[sname].size
                f.seek(s.offset)
                progbits[sname].data += bytearray(f.read(s.size))
            elif s.type == 2:  # SYMTAB
                strtab_shdr = shdrs[s.link]
                f.seek(strtab_shdr.offset)
                strtab = f.read(strtab_shdr.size)

                for sym in __read_struct_array(f, Elf64_Sym, s.size // s.entsize, offset=s.offset):
                    tu.symbols.append(Symbol(name=create_string_buffer(strtab[sym.name:]).value, value=sym.value, size=sym.size,
                                             type=ELF64_ST_TYPE(sym.info), bind=ELF64_ST_BIND(sym.info),
                                             sect=section_names[sym.shndx] if 0 < sym.shndx < len(shdrs) else None))
            elif s.type == 4:  # RELA
                related_sname = section_names[s.info]
                related_symtab = section_names[s.link]
                relas = __read_struct_array(f, Elf64_Rela, s.size // s.entsize, offset=s.offset)
                tu.relas.append((related_sname, relas))
                plt_num_entries += reduce(lambda acc, r: acc + int(ELF64_R_TYPE(r.info) in (R_x86_64_PLT32,)), relas, 0)
                rela_num_entries += reduce(lambda acc, r: acc + int(ELF64_R_TYPE(r.info) in (R_x86_64_64,)), relas, 0)
            elif s.type == 8:  # NOBITS
                # tu.bss_offset = bss_size
                tu.progbits_offset[sname] = bss_size
                bss_size += s.size
            else:
                pass

    # Step 2: Symbol resolution.
    symbol_dict = {} # TODO: Decide: whether it make sense to store in dict only global symbols.
    symbol_dict[b'\0'] = Symbol()
    for tu in tus:
        for sym in tu.symbols[1:]:
            if sym.type in (STT_FUNC, STT_OBJECT, STT_NOTYPE):
                if sym.name not in symbol_dict or symbol_dict[sym.name].sect is None:
                    symbol_dict[sym.name] = sym
                elif sym.bind == symbol_dict[sym.name].bind == STB_GLOBAL:
                    print("Multiple definition of symbol '%b'." % sym.name)

    symbol_dict[b'_GLOBAL_OFFSET_TABLE_'] = Symbol(
        name=b'_GLOBAL_OFFSET_TABLE_', value=0, size=0x8,
        type=STT_OBJECT, bind=STB_LOCAL, sect=b'.got.plt'
    )
    symbol_dict[b'_DYNAMIC'] = Symbol(
        name=b'_DYNAMIC', value=0, size=0x8,
        type=STT_OBJECT, bind=STB_LOCAL, sect=b'.dynamic'
    )

    print('-' * 25, 'SYMBOLS', '-' * 25)
    for name, sym in symbol_dict.items():
        print('%15s => %s' % (name, sym.sect))

    # Prepare final sections.
    # -----------------------
    res_sections = {}

    # Specify dynamic interpretor path.
    res_sections[b'.interp'] = Section(type=1, flags=SHF_ALLOC, data=b'/lib64/ld-linux-x86-64.so.2\0')

    # @Note: we specify only worst-case size estimate. Complete dynamic table filling will be performed
    # after the addresses are calculated.
    res_sections[b'.dynamic'] = FixedSection(type=6, flags=SHF_ALLOC | SHF_WRITE, size=(len(libs) + 25) * __struct_size(Elf64_Dyn))

    # Build symbol table (and related strtab) for dynamic linker.
    dynsyms = filter(lambda sym: sym.sect is None, symbol_dict.values())
    res_sections[b'.dynsym'] = FixedSection(type=11, flags=SHF_ALLOC, size=len(list(dynsyms)) * __struct_size(Elf64_Sym))
    res_sections[b'.dynstr'] = FixedSection(
        type=3, flags=SHF_ALLOC, size=sum(map(lambda x: len(x) + 1, chain(symbol_dict, libs))) + 1, data=b'\0')

    #
    res_sections[b'.got.plt'] = FixedSection(type=1, flags=SHF_ALLOC | SHF_WRITE, size=(3 + plt_num_entries) * struct_sz[Elf64_Addr], data=b'\0' * 0x8 * 3)
    res_sections[b'.plt'] = FixedSection(type=1, flags=SHF_ALLOC | SHF_EXECINSTR, size=0x10 + plt_num_entries * 0x10 + 0x50)

    # Create relocation table section with accurate estimate of its size.
    res_sections[b'.rela'] = FixedSection(type=4, flags=SHF_ALLOC, size=rela_num_entries * __struct_size(Elf64_Rela))
    res_sections[b'.rela.plt'] = FixedSection(type=4, flags=SHF_ALLOC, size=plt_num_entries * __struct_size(Elf64_Rela))

    # Build complete symbol table. Just to be.
    # TODO: Check whether ALLOC for following sections is actualy needed.
    res_sections[b'.symtab'] = FixedSection(type=2, flags=SHF_ALLOC, size=len(symbol_dict) * __struct_size(Elf64_Sym))
    res_sections[b'.strtab'] = FixedSection(
        type=3, flags=SHF_ALLOC, size=sum(map(lambda x: len(x) + 1, symbol_dict)) + 1, data=b'\0')

    # Add early loaded from object files and joined progbits sections.
    for sname, s in progbits.items():
        res_sections[sname] = s
    res_sections[b'.bss'] = FixedSection(type=8, flags=SHF_ALLOC | SHF_WRITE, size=bss_size)
    res_sections[b'.shstrtab'] = FixedSection(type=3, flags=SHF_ALLOC,
                                              size=200 + 0 * sum(map(lambda sname: len(sname) + 1, res_sections)) + 1)

    print('-' * 25, 'SECTION FLAGS', '-' * 25)
    keyfunc = lambda x: x[1].flags
    for f, ss in groupby(sorted(res_sections.items(), key=keyfunc), keyfunc):
        print('FLAGS: %s' % bin(f))
        for sname, s in ss:
            print('  %-15s => %s' % (sname, s.size))

    # Step 3: Build section layout (compute section offsets).
    ehdr_offset = 0
    ehdr_size = __struct_size(Elf64_Hdr)
    phdr_offset = ehdr_offset + ehdr_size
    phdr_entsize = __struct_size(Elf64_Phdr)
    phdr_size = 10 * phdr_entsize
    sections_offset = phdr_offset + phdr_size

    section_names = (b'.interp', b'.dynamic', b'.symtab', b'.strtab',
                     b'.rela', b'.rela.plt', b'.plt', b'.text',
                     b'.rodata', b'.got', b'.got.plt', b'.data', b'.bss')

    # res_sections[b'.symtab'] = FixedSection(size=len(symbol_dict) * __struct_size(Elf64_Sym))
    # res_sections[b'.strtab'] = FixedSection(size=sum(map(lambda s: len(s.name), symbol_dict.values())))
    # res_sections[b'.dynamic'] = FixedSection(size=(len(libs) + 50) * __struct_size(Elf64_Dyn))
    # if got_num_entries != 0:
    #     res_sections[b'.got'] = FixedSection(size=0x8 * got_num_entries)
    # if plt_num_entries != 0:
    #     res_sections[b'.got.plt'] = FixedSection(size=0x8 * plt_num_entries)
    #     res_sections[b'.plt'] = FixedSection(size=0x10 + plt_num_entries * 0x10)
    #     res_sections[b'.rela.plt'] = FixedSection(size=__struct_size(Elf64_Rela) * plt_num_entries)

    # rx_section_names = (b'.interp', b'.dynamic', b'.symtab', b'.strtab', b'.rela', b'.rela.plt', b'.plt', b'.text', b'.rodata')
    # rw_section_names = (b'.got', b'.got.plt', b'.data', b'.bss')
    rx_section_names = [sname for sname, s in filter(lambda s: s[1].flags == SHF_EXECINSTR | SHF_ALLOC or s[1].flags == SHF_ALLOC, res_sections.items())]
    rw_section_names = [sname for sname, s in filter(lambda s: s[1].flags == SHF_WRITE | SHF_ALLOC, res_sections.items())]
    print(rx_section_names)
    print(rw_section_names)

    addends = dict(chain(zip(rx_section_names, repeat(0x0)),
                         zip(rw_section_names, repeat(0x200000))))

    # @Note: In this point we must know sizes of all sections that reside in output files.
    offset = sections_offset
    for section_name in chain(rx_section_names, rw_section_names):
        sec = res_sections[section_name]
        sec.offset = offset
        sec.vaddr = offset + addends[section_name]
        offset += sec.estimated_size
        offset += 0x7
        offset &= ~0x7
    shdr_offset = offset
    shdr_entsize = __struct_size(Elf64_Shdr)

    print('-' * 25, 'SECTIONS', '-' * 25)
    for sname in chain(rx_section_names, rw_section_names):
        s = res_sections[sname]
        print('%15s => %#x:%#x' % (sname, s.offset, s.vaddr))

    section_index = {sname:i for i, sname in enumerate(chain(rx_section_names, rw_section_names))}

    rx_section_group_offset = res_sections[next(iter(rx_section_names))].offset
    rx_section_group_vaddr  = res_sections[next(iter(rx_section_names))].vaddr
    rx_section_group_size   = sum(map(lambda sn: res_sections[sn].estimated_size, rx_section_names))
    rw_section_group_offset = res_sections[next(iter(rw_section_names))].offset
    rw_section_group_vaddr  = res_sections[next(iter(rw_section_names))].vaddr
    rw_section_group_size   = sum(map(lambda sn: res_sections[sn].estimated_size, rw_section_names))

    # Fill .dynsym and .symtab sections.
    dynsym_last_local_bind = 0
    symtab_last_local_bind = 0
    for i, sym in enumerate(symbol_dict.values()):
        if sym.sect is None:
            print(i, sym.type)
            if sym.bind == STB_LOCAL:
                dynsym_last_local_bind = i
                symtab_last_local_bind = i
                print(i)
            res_sections[b'.dynsym'].data += __pack_struct(Elf64_Sym(
                name=res_sections[b'.dynstr'].size, info=ELF64_ST_INFO(sym.bind, sym.type), other=0,
                shndx=0, value=sym.value, size=sym.size))
            res_sections[b'.dynstr'].data += b'%s\0' % sym.name
            res_sections[b'.symtab'].data += __pack_struct(Elf64_Sym(
                name=res_sections[b'.strtab'].size, info=ELF64_ST_INFO(sym.bind, sym.type), other=0,
                shndx=0, value=sym.value, size=sym.size))
            res_sections[b'.strtab'].data += b'%s\0' % sym.name
        else:
            if sym.bind == STB_LOCAL:
                symtab_last_local_bind = i
            res_sections[b'.symtab'].data += __pack_struct(Elf64_Sym(
                name=res_sections[b'.strtab'].size, info=ELF64_ST_INFO(sym.bind, sym.type), other=0,
                shndx=section_index[sym.sect], value=res_sections[sym.sect].vaddr + sym.value, size=sym.size))
            res_sections[b'.strtab'].data += b'%s\0' % sym.name

    libstr_offsets = []
    for l in libs:
        libstr_offsets.append(res_sections[b'.dynstr'].size)
        res_sections[b'.dynstr'].data += b'%s\0' % bytes(l, 'utf-8')

    dynsyms = filter(lambda sym: sym.sect is None, symbol_dict.values())  # TODO: Remove it.
    sym_index = {sym.name: i for i, sym in enumerate(dynsyms)}

    # Symbols value field correction.
    # TODO: Fix possible bug.
    # for sym in filter(lambda sym: sym.sect is not None, symbol_dict.values()):
    #     print('-', sym.name, sym.sect, hex(res_sections[sym.sect].vaddr))
    #     sym.value += res_sections[sym.sect].vaddr
    for tu in tus:
        for sym in tu.symbols:
            if sym.sect is not None:
                sym.value += res_sections[sym.sect].vaddr + tu.progbits_offset[sym.sect]

    res_sections[b'.plt'].data = create_initial_plt_entry(
        (res_sections[b'.got.plt'].vaddr + 0x8) - (res_sections[b'.plt'].vaddr + 0x6),
        (res_sections[b'.got.plt'].vaddr + 0x10) - (res_sections[b'.plt'].vaddr + 0xc),
    )

    # Step 4: Perform relocations.
    for tu in tus:
        for related_sname, rs in tu.relas:
            for r in rs:
                r_type = ELF64_R_TYPE(r.info)
                r_sym = ELF64_R_SYM(r.info)

                if r_type == R_x86_64_64:
                    # S = res_sections[related_sname].vaddr + tu.symbols[related_sname].value + tu.symbols[r_sym].value
                    S = tu.symbols[r_sym].value
                    print('===')
                    print(hex(S))
                    A = r.addend
                    section_offset = tu.progbits_offset[related_sname] + r.offset
                    res_sections[related_sname].data[section_offset:section_offset+8] = bytearray(pack('Q', S + A))
                    res_sections[b'.rela'].data += __pack_struct(Elf64_Rela(
                        res_sections[related_sname].vaddr + section_offset, ELF64_R_INFO(0, R_x86_64_RELATIVE), S + A))
                elif r_type == R_x86_64_PC32:
                    # S = res_sections[tu.symbols[r_sym].sect].vaddr + tu.progbits_offset[tu.symbols[r_sym].sect] + tu.symbols[r_sym].value
                    S = tu.symbols[r_sym].value
                    A = r.addend
                    section_offset = tu.progbits_offset[related_sname] + r.offset
                    P = res_sections[related_sname].vaddr + section_offset
                    print('---')
                    print(hex(S))
                    print(hex(P))
                    print(hex(tu.symbols[r_sym].value))
                    res_sections[related_sname].data[section_offset:section_offset+4] = bytearray(pack('i', S + A - P))
                elif r_type == R_x86_64_PLT32:
                    L = res_sections[b'.plt'].vaddr + res_sections[b'.plt'].size
                    print('888', res_sections[b'.rela.plt'].size // __struct_size(Elf64_Rela))
                    res_sections[b'.plt'].data += create_plt_entry(
                        (res_sections[b'.got.plt'].vaddr + res_sections[b'.got.plt'].size) - (res_sections[b'.plt'].vaddr + res_sections[b'.plt'].size + 0x6),
                        res_sections[b'.rela.plt'].size // __struct_size(Elf64_Rela),
                        -(res_sections[b'.plt'].size + 0x10))
                    res_sections[b'.rela.plt'].data += __pack_struct(Elf64_Rela(
                        res_sections[b'.got.plt'].vaddr + res_sections[b'.got.plt'].size, ELF64_R_INFO(sym_index[tu.symbols[r_sym].name], R_x86_64_JUMP_SLOT), 0x0))
                    res_sections[b'.got.plt'].data += pack('q', (res_sections[b'.plt'].vaddr + res_sections[b'.plt'].size - 0x10 + 0x6))

                    A = r.addend
                    section_offset = tu.progbits_offset[related_sname] + r.offset
                    P = res_sections[related_sname].vaddr + section_offset
                    res_sections[related_sname].data[section_offset:section_offset+4] = bytearray(pack('i', L + A - P))
                else:
                    pass

    # Step 5: Building .dynamic section.
    print(res_sections[b'.strtab'].data)
    for lo in libstr_offsets:
        print(lo)
        print(create_string_buffer(res_sections[b'.strtab'].data[lo:]).value)
    res_sections[b'.dynamic'].data += __pack_struct_array(Elf64_Dyn(DT_NEEDED, lo) for lo in libstr_offsets)
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_STRTAB, res_sections[b'.dynstr'].vaddr))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_SYMTAB, res_sections[b'.dynsym'].vaddr))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_STRSZ, res_sections[b'.dynstr'].size))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_SYMENT, __struct_size(Elf64_Sym)))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_PLTGOT, res_sections[b'.got.plt'].vaddr))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_PLTRELSZ, res_sections[b'.rela.plt'].size))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_PLTREL, DT_RELA))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_JMPREL, res_sections[b'.rela.plt'].vaddr))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_RELA, res_sections[b'.rela'].vaddr))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_RELASZ, res_sections[b'.rela'].size + res_sections[b'.rela.plt'].size))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_RELAENT, __struct_size(Elf64_Rela)))
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(0x6ffffffb, 0x8000000))  # Flags: PIE
    res_sections[b'.dynamic'].data += __pack_struct(Elf64_Dyn(DT_NULL, 0))

    # Building program header.
    phdrs = []
    phdrs.append(Elf64_Phdr(PT_PHDR, flags=PF_R, offset=phdr_offset, vaddr=phdr_offset, paddr=phdr_offset, filesz=phdr_size, memsz=phdr_size, align=2**3))
    phdrs.append(Elf64_Phdr(PT_INTERP, flags=PF_R, offset=res_sections[b'.interp'].offset, vaddr=res_sections[b'.interp'].vaddr, paddr=res_sections[b'.interp'].vaddr,
                            filesz=res_sections[b'.interp'].size, memsz=res_sections[b'.interp'].size, align=2**0))
    phdrs.append(Elf64_Phdr(PT_LOAD, flags=PF_R | PF_X, offset=0x0, vaddr=0x0, paddr=0x0,
                            filesz=ehdr_size + phdr_size + rx_section_group_size, memsz=ehdr_size + phdr_size + rx_section_group_size, align=2**21))
    phdrs.append(Elf64_Phdr(PT_LOAD, flags=PF_R | PF_W, offset=rw_section_group_offset, vaddr=rw_section_group_vaddr, paddr=rw_section_group_vaddr,
                            filesz=rw_section_group_size, memsz=rw_section_group_size, align=2**21))
    phdrs.append(Elf64_Phdr(PT_DYNAMIC, flags=PF_R | PF_W, offset=res_sections[b'.dynamic'].offset, vaddr=res_sections[b'.dynamic'].vaddr, paddr=res_sections[b'.dynamic'].vaddr,
                            filesz=res_sections[b'.dynamic'].size, memsz=res_sections[b'.dynamic'].size, align=2**3))

    shdrs = []
    res_sections[b'.shstrtab'].data = b'\0'
    for sname in chain(rx_section_names, rw_section_names):
        s = res_sections[sname]
        shdrs.append(Elf64_Shdr(name=res_sections[b'.shstrtab'].size, type=s.type, flags=s.flags,
                                addr=s.vaddr, offset=s.offset, size=s.estimated_size,
                                link=0, info=0, addralign=0, entsize=0))
        res_sections[b'.shstrtab'].data += b'%s\0' % sname

    shdrs[section_index[b'.dynsym']].entsize = __struct_size(Elf64_Sym)
    shdrs[section_index[b'.dynsym']].link = section_index[b'.dynstr']
    shdrs[section_index[b'.dynsym']].info = dynsym_last_local_bind + 1
    shdrs[section_index[b'.rela']].entsize = __struct_size(Elf64_Rela)
    shdrs[section_index[b'.rela']].link = section_index[b'.symtab']
    shdrs[section_index[b'.rela.plt']].entsize = __struct_size(Elf64_Rela)
    shdrs[section_index[b'.rela.plt']].link = section_index[b'.dynsym']
    shdrs[section_index[b'.symtab']].entsize = __struct_size(Elf64_Sym)
    shdrs[section_index[b'.symtab']].link = section_index[b'.strtab']
    shdrs[section_index[b'.symtab']].info = symtab_last_local_bind + 1
    shdrs[section_index[b'.dynamic']].link = section_index[b'.dynstr']


    # Elf
    ehdr.type = ET_DYN
    ehdr.entry = symbol_dict[b'_start'].value
    ehdr.phoff = phdr_offset
    ehdr.shoff = shdr_offset
    ehdr.phentsize = phdr_entsize
    ehdr.phnum = len(phdrs)
    ehdr.shentsize = shdr_entsize
    ehdr.shnum = len(shdrs)
    ehdr.shstrndx = section_index[b'.shstrtab']  # Don't care about.

    print('-' * 25, 'RESULT EHDR', '-' * 25)
    for x in asdict(ehdr).items():
        print('%10s => %s' % x)

    # Step 7: Writing result.
    __write_struct(fout, ehdr)
    __write_struct_array(fout, phdrs, offset=phdr_offset)
    for sname in chain(rx_section_names, rw_section_names):
        sec = res_sections[sname]
        fout.seek(sec.offset)
        fout.write(sec.data)
    __write_struct_array(fout, shdrs, offset=shdr_offset)

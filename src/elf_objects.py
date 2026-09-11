"""Minimal ELF32 big-endian reader for the objects dtk-template builds.

Only what symbol derivation needs: the symbol table, and the relocations that
land inside each function. `dtk elf info` reports a relocation *count* and
nothing more, and this project is deliberately dependency-free, so the few
structures involved are decoded here rather than taking on pyelftools.
"""

from __future__ import annotations

import struct

SHT_SYMTAB = 2
SHT_RELA = 4
SHN_UNDEF = 0
STT_FUNC = 2
STB_LOCAL = 0


def read_object(path):
    """Parse one relocatable object into sections, symbols and `.text` functions."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 2:
        raise ValueError(f"{path}: not a 32-bit big-endian ELF")
    (table,) = struct.unpack_from(">I", data, 32)
    entry_size, count, names_index = struct.unpack_from(">HHH", data, 46)

    def header(index):
        # sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
        # sh_info, sh_addralign, sh_entsize
        return struct.unpack_from(">10I", data, table + index * entry_size)

    def text_at(base, offset):
        end = data.index(b"\0", base + offset)
        return data[base + offset : end].decode("utf-8", "replace")

    names = header(names_index)[4]
    sections = []
    for index in range(count):
        name, kind, _, _, offset, size, link, _, _, _ = header(index)
        sections.append(
            {
                "name": text_at(names, name),
                "type": kind,
                "offset": offset,
                "size": size,
                "link": link,
                "index": index,
            }
        )

    symbols = []
    table_section = next((s for s in sections if s["type"] == SHT_SYMTAB), None)
    if table_section is not None:
        strings = sections[table_section["link"]]["offset"]
        for index in range(table_section["size"] // 16):
            offset = table_section["offset"] + index * 16
            name, value, size, info, _, shndx = struct.unpack_from(
                ">IIIBBH", data, offset
            )
            symbols.append(
                {
                    "name": text_at(strings, name),
                    "value": value,
                    "size": size,
                    "type": info & 0xF,
                    "bind": info >> 4,
                    "shndx": shndx,
                }
            )

    functions = _text_functions(data, sections, symbols)
    return {
        "path": path,
        "sections": {s["name"]: s for s in sections if s["name"]},
        "symbols": symbols,
        "functions": functions,
    }


def _text_functions(data, sections, symbols):
    """`.text` functions in address order, each carrying its relocations in order."""
    text = next((s for s in sections if s["name"] == ".text"), None)
    if text is None:
        return []
    functions = [
        {
            "name": s["name"],
            "value": s["value"],
            "size": s["size"],
            "local": s["bind"] == STB_LOCAL,
            "relocations": [],
        }
        for s in symbols
        if s["shndx"] == text["index"] and s["type"] == STT_FUNC and s["size"]
    ]
    functions.sort(key=lambda f: f["value"])

    relocations = next(
        (
            s
            for s in sections
            if s["type"] == SHT_RELA and s["name"] == ".rela" + text["name"]
        ),
        None,
    )
    if relocations is None:
        return functions
    entries = []
    for index in range(relocations["size"] // 12):
        offset, info, addend = struct.unpack_from(
            ">IIi", data, relocations["offset"] + index * 12
        )
        target = symbols[info >> 8]
        entries.append(
            {
                "offset": offset,
                "type": info & 0xFF,
                "addend": addend,
                "target": target["name"],
                "external": target["shndx"] == SHN_UNDEF,
            }
        )
    entries.sort(key=lambda e: e["offset"])
    # Relocations are attributed to the function whose body contains them, which
    # is what turns a flat relocation table into a per-function call list.
    bounds = [(f["value"], f["value"] + f["size"], f) for f in functions]
    for entry in entries:
        for start, end, function in bounds:
            if start <= entry["offset"] < end:
                function["relocations"].append(entry)
                break
    return functions

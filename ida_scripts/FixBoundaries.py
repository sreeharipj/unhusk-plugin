# IDAPython port of ghidra_scripts/FixBoundaries.py.
#
# Not tested inside IDA -- written from the API docs (IDA 7.4+). Calls to
# verify are marked "# CHECK"; the Ghidra script is the tested reference.
#
# Replaces IDA's function extents with unhusk's --boundaries feed, which comes
# from .eh_frame (ELF) and .pdata (PE). Against DWARF those extents are
# start-and-end exact 99.9% of the time, versus 73.3% for angr CFGFast and
# 62.9% for Ghidra headless: a disassembler infers the end from control flow
# and stops early on a tail call or an unresolved jump table.
#
# Run:  idat64 -A -L/tmp/fb.log -S"FixBoundaries.py boundaries.json" target
#   or  File > Script file... in the GUI.

import json

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_nalt
import ida_ua
import idc

try:
    import ida_ida

    def filetype():
        return ida_ida.inf_get_filetype()                     # CHECK: 7.4+ name
except ImportError:
    def filetype():
        return idc.get_inf_attr(idc.INF_FILETYPE)             # 7.0-7.3


def script_arg():
    argv = idc.ARGV
    if len(argv) > 1:
        return argv[1]
    path = ida_kernwin.ask_file(False, "*.json", "unhusk --boundaries JSON")
    if not path:
        raise SystemExit("FixBoundaries: no boundaries file given")
    return path


def to_ea(offset, fmt, image_base):
    # PE: unhusk emits an RVA -> image_base + RVA.
    # ELF: unhusk emits the file's p_vaddr, and IDA maps ELF segments there
    # unchanged (no equivalent of Ghidra's 0x100000 x86-64 default). Add
    # (current base - original base) if you rebased the database.
    if fmt == "pe":
        return image_base + offset
    return offset


def check_format(fmt):
    ft = filetype()
    if fmt == "pe" and ft != idc.FT_PE:
        print("unhusk-plugin: WARNING -- feed says pe, IDB filetype is %d" % ft)
    elif fmt == "elf" and ft != idc.FT_ELF:
        print("unhusk-plugin: WARNING -- feed says elf, IDB filetype is %d" % ft)


def clear_overlapping(start, end):
    """Delete every function overlapping [start, end). True if one was there,
    so the caller can tell 'corrected' from 'created'."""
    removed = False
    ea = start
    while ea < end:
        f = ida_funcs.get_func(ea)                            # CHECK: any ea inside func
        if f is None:
            ea += 1
            continue
        nxt = f.end_ea
        ida_funcs.del_func(f.start_ea)
        removed = True
        ea = max(ea + 1, nxt)
    if start > 0:
        f = ida_funcs.get_func(start - 1)
        if f is not None and f.end_ea > start:                # a merge reaching in from below
            ida_funcs.del_func(f.start_ea)
            removed = True
    return removed


def main():
    with open(script_arg(), "rb") as fp:
        data = json.loads(fp.read())
    fmt = data.get("format", "")
    check_format(fmt)
    image_base = ida_nalt.get_imagebase()
    funcs = data.get("functions", [])
    print("unhusk-plugin: %d boundaries from %s (%s)"
          % (len(funcs), data.get("binary", "?"), fmt or "?"))

    matched = corrected = created = failed = 0

    for entry in sorted(funcs, key=lambda e: int(e["start"], 16)):
        start = to_ea(int(entry["start"], 16), fmt, image_base)
        end = to_ea(int(entry["end"], 16), fmt, image_base)
        if end <= start:
            failed += 1
            continue

        f = ida_funcs.get_func(start)
        if f is not None and f.start_ea == start and f.end_ea == end:
            matched += 1
            continue

        had_func = clear_overlapping(start, end)
        ida_bytes.del_items(start, ida_bytes.DELIT_SIMPLE, end - start)  # CHECK: (ea, flags, nbytes)
        ok = ida_funcs.add_func(start, end)                   # explicit end -> no auto-follow
        if not ok:
            ida_ua.create_insn(start)                         # head must be code first
            ok = ida_funcs.add_func(start, end)
        if not ok:
            failed += 1
            print("unhusk-plugin: could not create function at %#x..%#x" % (start, end))
            continue

        g = ida_funcs.get_func(start)
        if g is not None and g.end_ea != end:
            ida_funcs.set_func_end(start, end)                # CHECK: (ea_in_func, new_end)
        corrected += 1 if had_func else 0
        created += 0 if had_func else 1

    ida_auto.auto_wait()
    print("unhusk-plugin: matched=%d corrected=%d created=%d failed=%d total=%d"
          % (matched, corrected, created, failed, len(funcs)))


main()

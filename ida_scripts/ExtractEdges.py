# IDAPython port of ghidra_scripts/ExtractEdges.py.
#
# Not tested inside IDA -- written from the API docs (IDA 7.4+). Calls to
# verify are marked "# CHECK".
#
# Resolves each core::panic::Location unhusk recovered to its containing
# function using IDA's cross-references, and writes a
# {location -> [function start]} map for `unhusk --json --tier-from`. unhusk
# still ranks the functions; this supplies the "which function" step from
# xrefs IDA built during analysis instead of unhusk's x86-64 decode pass, so
# it is not tied to one architecture. Run FixBoundaries.py first. Coverage
# must be re-measured per architecture (see ../README.md).
#
# Run:  idat64 -A -L/tmp/ee.log -S"ExtractEdges.py locations.json edges.json" target.i64

import json

import ida_funcs
import ida_kernwin
import ida_nalt
import idautils
import idc

try:
    import ida_ida

    def is_64bit():
        return ida_ida.inf_is_64bit()                         # CHECK: 7.4+ name
except ImportError:
    def is_64bit():
        return idc.get_inf_attr(idc.INF_LFLAGS) & idc.LFLG_64BIT != 0


def script_args():
    argv = idc.ARGV
    loc = argv[1] if len(argv) > 1 else ida_kernwin.ask_file(
        False, "*.json", "unhusk --locations JSON")
    if not loc:
        raise SystemExit("ExtractEdges: no locations file given")
    out = argv[2] if len(argv) > 2 else ida_kernwin.ask_file(
        True, "edges.json", "write edges JSON to")
    if not out:
        raise SystemExit("ExtractEdges: no output path given")
    return loc, out


def struct_len():
    # &str (ptr + len) + u32 line + u32 col: 24 on 64-bit, 16 on 32-bit.
    return 24 if is_64bit() else 16


def main():
    loc_path, out_path = script_args()
    with open(loc_path, "rb") as fp:
        data = json.loads(fp.read())

    fmt = data.get("format", "")
    image_base = ida_nalt.get_imagebase()
    slen = struct_len()
    locs = data.get("locations", [])

    def to_ea(v):
        return image_base + v if fmt == "pe" else v

    def to_unhusk(ea):
        return ea - image_base if fmt == "pe" else ea

    edges = {}
    attributed = no_container = midstruct = 0

    for entry in locs:
        v = int(entry["addr"], 16)
        base = to_ea(v)
        starts = set()
        for k in range(slen):
            for xr in idautils.XrefsTo(base + k, 0):          # CHECK: yields .frm
                if k > 0:
                    midstruct += 1
                f = ida_funcs.get_func(xr.frm)
                if f is not None:
                    starts.add(to_unhusk(f.start_ea))
        if starts:
            edges["0x%x" % v] = sorted("0x%x" % s for s in starts)
            attributed += 1
        else:
            no_container += 1

    out = {
        "tool": "unhusk-plugin ExtractEdges",
        "binary": data.get("binary", "?"),
        "format": fmt,
        "struct_len": slen,
        "edges": edges,
    }
    with open(out_path, "w") as fp:
        json.dump(out, fp, indent=1)

    total = sum(len(v) for v in edges.values())
    print("unhusk-plugin: %d Location(s) -> %d attributed (%d edges), %d with no function"
          % (len(locs), attributed, total, no_container))
    print("unhusk-plugin: %d xref(s) landed past the struct head" % midstruct)
    if no_container:
        print("unhusk-plugin: run FixBoundaries.py first; some loss on functions with "
              "unresolved jump tables is expected.")
    print("unhusk-plugin: wrote %s" % out_path)


main()

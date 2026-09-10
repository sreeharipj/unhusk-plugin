# Resolves each core::panic::Location unhusk recovered to its containing
# function using Ghidra's cross-references, and writes a
# {location -> [function start]} map for `unhusk --json --tier-from`. unhusk
# still ranks the functions; this only supplies the "which function" step,
# from references Ghidra built during analysis rather than unhusk's own
# x86-64 decode pass.
#
# Run after FixBoundaries.py so getFunctionContaining has the right bodies.
# On x86-64 this under-reports where Ghidra left code undisassembled and never
# over-reports; see ../README.md for the numbers, and re-measure per target.
#
# Usage:
#   unhusk <binary> --locations > locations.json
#   analyzeHeadless <project> <name> -process <binary> \
#     -scriptPath /path/to/unhusk-plugin/ghidra_scripts \
#     -postScript ExtractEdges.py locations.json edges.json
#   unhusk <binary> --json --tier-from edges.json > triage.json
#@category Analysis
#@runtime Jython

from ghidra.app.util.opinion import ElfLoader

import json


def load_locations():
    args = getScriptArgs()
    if len(args) > 0:
        loc_path = args[0]
    else:
        loc_path = askFile("unhusk --locations JSON", "Choose file").getAbsolutePath()
    if len(args) > 1:
        out_path = args[1]
    else:
        out_path = askFile("write edges JSON to", "Save").getAbsolutePath()
    with open(loc_path, "rb") as fp:
        return json.loads(fp.read()), out_path


def to_ghidra_addr(offset, fmt, image_base, elf_original_base):
    if fmt == "pe":
        return image_base.add(offset)
    base = elf_original_base if elf_original_base is not None else 0
    return image_base.add(offset - base)


def struct_len():
    # &str (ptr + len) + u32 line + u32 col: 24 on 64-bit, 16 on 32-bit.
    return 2 * currentProgram.getDefaultPointerSize() + 8


def run(data, out_path):
    fmt = data.get("format", "")
    prog_fmt = currentProgram.getExecutableFormat() or ""
    if fmt and fmt.upper() not in prog_fmt:
        print("unhusk-plugin: WARNING -- locations file says {}, program looks like {}"
              .format(fmt, prog_fmt))

    image_base = currentProgram.getImageBase()
    elf_original_base = ElfLoader.getElfOriginalImageBase(currentProgram)
    fm = currentProgram.getFunctionManager()
    slen = struct_len()
    locs = data.get("locations", [])
    vaddr_off = image_base.getOffset()
    if fmt != "pe":
        vaddr_off -= (elf_original_base or 0)

    edges = {}
    attributed = no_container = midstruct = 0

    for entry in locs:
        if monitor.isCancelled():
            break
        loc_v = int(entry["addr"], 16)
        base = to_ghidra_addr(loc_v, fmt, image_base, elf_original_base)
        starts = set()
        for k in range(slen):
            for r in getReferencesTo(base.add(k)):
                if k > 0:
                    midstruct += 1
                f = fm.getFunctionContaining(r.getFromAddress())
                if f is not None:
                    starts.add(f.getEntryPoint().getOffset() - vaddr_off)
        if starts:
            edges["0x{:x}".format(loc_v)] = sorted("0x{:x}".format(a) for a in starts)
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
    with open(out_path, "wb") as fp:
        fp.write(json.dumps(out, indent=1))

    total = sum(len(v) for v in edges.values())
    print("unhusk-plugin: {} Location(s) -> {} attributed ({} edges), {} with no containing function"
          .format(len(locs), attributed, total, no_container))
    print("unhusk-plugin: {} reference(s) landed past the struct head".format(midstruct))
    if no_container:
        print("unhusk-plugin: run FixBoundaries.py first; some loss on functions with "
              "unresolved jump tables is expected.")
    print("unhusk-plugin: wrote {}".format(out_path))


data, out_path = load_locations()
run(data, out_path)

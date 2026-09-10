# Marks the functions unhusk's --json feed attributes to author code: a
# Bookmark (category "unhusk") and a plate comment listing the recovered
# source paths, at each STRONG/SINGLE-tier function. It does not rename.
#
# Run after FixBoundaries.py. If the function at a feed address is still wrong
# or missing, the annotation falls back to the containing function and logs it.
#
# Usage:
#   unhusk <binary> --json > triage.json
#   analyzeHeadless <project> <name> -process <binary> \
#     -scriptPath /path/to/unhusk-plugin/ghidra_scripts \
#     -postScript FixBoundaries.py boundaries.json \
#     -postScript ApplyUnhusk.py  triage.json
# or from the Script Manager, which prompts for the file.
#
# Address translation (to_ghidra_addr) is the only format-specific part, and is
# the same as FixBoundaries.py.
#@category Analysis
#@runtime Jython

from ghidra.app.util.opinion import ElfLoader

import json

MARKER = "unhusk:"
BOOKMARK_CATEGORY = "unhusk"


def load_feed():
    args = getScriptArgs()
    if len(args) > 0:
        path = args[0]
    else:
        path = askFile("unhusk --json triage feed", "Choose file").getAbsolutePath()
    with open(path, "rb") as fp:
        return json.loads(fp.read())


def check_arch(data):
    feed_arch = (data.get("arch") or "").lower()
    lang = str(currentProgram.getLanguageID()).lower()
    if ("x86-64" in feed_arch or "x86_64" in feed_arch) and ("x86" not in lang or "64" not in lang):
        print("unhusk-plugin: WARNING -- feed arch is {} but program language is {}"
              .format(feed_arch, lang))


def to_ghidra_addr(offset, fmt, image_base, elf_original_base):
    if fmt == "pe":
        return image_base.add(offset)
    base = elf_original_base if elf_original_base is not None else 0
    return image_base.add(offset - base)


def program_format():
    return "pe" if "PE" in (currentProgram.getExecutableFormat() or "") else "elf"


def plate_block(fn, rule):
    n = fn.get("anchor_count", 0)
    lines = ["{} {} ({}, {} anchor{})".format(
        MARKER, fn.get("tier", "?").upper(), rule, n, "" if n == 1 else "s")]
    for p in fn.get("anchor_files", []):
        lines.append("  " + p)
    return "\n".join(lines)


def merge_plate(addr, block):
    """Set the plate comment to `block`, keeping any text that isn't a prior
    unhusk block. Returns 'set', 'updated', or 'unchanged'."""
    existing = getPlateComment(addr)
    if not existing:
        setPlateComment(addr, block)
        return "set"
    kept = []
    skipping = False
    for line in existing.split("\n"):
        if line.startswith(MARKER):
            skipping = True
            continue
        if skipping:
            if line.strip() == "":
                skipping = False
            elif line.startswith("  "):
                continue
            else:
                skipping = False
        if not skipping:
            kept.append(line)
    kept_text = "\n".join(kept).strip("\n")
    new_text = block if kept_text == "" else block + "\n\n" + kept_text
    if new_text == existing:
        return "unchanged"
    setPlateComment(addr, new_text)
    return "updated"


def apply_feed(data):
    image_base = currentProgram.getImageBase()
    elf_original_base = ElfLoader.getElfOriginalImageBase(currentProgram)
    fmt = program_format()
    fm = currentProgram.getFunctionManager()
    bm = currentProgram.getBookmarkManager()
    functions = data.get("functions", [])
    rule = data.get("rule", "?")

    print("unhusk-plugin: {} triage functions from {} (rule {}, arch {})".format(
        len(functions), data.get("binary", "?"), rule, data.get("arch", "?")))
    if fmt == "elf":
        print("unhusk-plugin: image_base={} elf_original_base={}".format(
            image_base, elf_original_base))

    annotated = at_container = no_function = plate_written = 0

    for fn in sorted(functions, key=lambda e: int(e["start"], 16)):
        if monitor.isCancelled():
            break

        start = int(fn["start"], 16)
        addr = to_ghidra_addr(start, fmt, image_base, elf_original_base)

        target = fm.getFunctionAt(addr)
        anchor_addr = addr
        note_suffix = ""
        if target is None:
            containing = fm.getFunctionContaining(addr)
            if containing is not None:
                anchor_addr = containing.getEntryPoint()
                note_suffix = " (feed start 0x{:x} is +{} into this function; run FixBoundaries.py first)".format(
                    start, addr.subtract(anchor_addr))
                at_container += 1
            else:
                no_function += 1

        comment = "unhusk {} tier | {} | {} anchor(s) | {}{}".format(
            fn.get("tier", "?"), rule, fn.get("anchor_count", 0),
            ", ".join(fn.get("anchor_files", [])), note_suffix)
        bm.setBookmark(anchor_addr, "Note", BOOKMARK_CATEGORY,
                       "[{}] {}".format(fn.get("tier", "?"), comment))

        if fm.getFunctionAt(anchor_addr) is not None or target is not None:
            if merge_plate(anchor_addr, plate_block(fn, rule)) in ("set", "updated"):
                plate_written += 1
        annotated += 1

    print("unhusk-plugin: annotated={} (plate comments={}), at-containing-function={}, no-function={}".format(
        annotated, plate_written, at_container, no_function))
    if at_container or no_function:
        print("unhusk-plugin: run FixBoundaries.py first so feed addresses hit exact starts.")


data = load_feed()
check_arch(data)
apply_feed(data)

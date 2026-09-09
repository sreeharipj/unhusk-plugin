# Corrects Ghidra's function boundaries to match unhusk's --boundaries feed:
# ground truth from the container format's own unwind metadata (.eh_frame
# FDEs on ELF, .pdata RUNTIME_FUNCTION entries on PE), which both survive
# strip --strip-all because unwinding needs them. See unhusk-ghidra/README.md.
#
# Ghidra's own function-start heuristics are unreliable on stripped,
# optimized Rust: merged functions, missed starts, tail-call and jump-table
# confusion. This script makes Ghidra's function model match unhusk's exactly
# -- skips what's already correct, force-recreates what isn't with an
# explicit body (CreateFunctionCmd, not Ghidra's auto-follow, so it can't
# over/undershoot). It runs on every function in the binary and has nothing
# to do with unhusk's panic-Location triage specifically; that's the next
# script, ApplyUnhusk.py, which should run only after this one.
#
# Usage:
#   unhusk <binary> --boundaries > boundaries.json
# then, with the same binary loaded in Ghidra:
#   analyzeHeadless <project> <name> -process <binary> \
#     -scriptPath /path/to/unhusk-ghidra/ghidra_scripts \
#     -postScript FixBoundaries.py boundaries.json
# or run it from the Script Manager, which prompts for the JSON file.
#
# No architecture-specific code: this only ever reads an address from JSON
# and acts on it in the currently loaded program, and Ghidra's addressing
# API is arch-neutral already. The one format-specific piece is address
# translation -- see to_ghidra_addr() below -- not instruction decoding.
#
# @runtime pins this to Jython explicitly. Ghidra 12.x bundles PyGhidra
# alongside Jython and gives it @ExtensionPointProperties(priority = 1000)
# specifically so it wins any unmarked .py file -- confirmed against a
# local Ghidra source clone (PyGhidraScriptProvider.java) after this script
# failed headless with "Ghidra was not started with PyGhidra" despite never
# invoking pyghidraRun. Without this tag every claim in this repo's README
# about Jython being the zero-setup default is simply wrong on Ghidra 12.x.
#@category Analysis
#@runtime Jython

from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.util.opinion import ElfLoader
from ghidra.program.model.address import AddressSet
from ghidra.program.model.symbol import SourceType

import json


def load_boundaries():
    args = getScriptArgs()
    if len(args) > 0:
        path = args[0]
    else:
        f = askFile("unhusk boundaries JSON", "Choose file")
        path = f.getAbsolutePath()
    with open(path, "rb") as fp:
        return json.loads(fp.read())


def check_format(data):
    # Soft mismatch warning only, never a gate -- see the module docstring
    # in unhusk's container/mod.rs: the point of the container seam is that
    # nothing downstream needs to special-case format, and this script
    # follows the same rule. Wrong-file-picked is the only thing this is
    # trying to catch.
    fmt = data.get("format", "")
    exec_fmt = currentProgram.getExecutableFormat() or ""
    if fmt == "elf" and "ELF" not in exec_fmt:
        print("unhusk-ghidra: WARNING -- boundaries file says elf, loaded program looks like {}".format(exec_fmt))
    elif fmt == "pe" and "PE" not in exec_fmt:
        print("unhusk-ghidra: WARNING -- boundaries file says pe, loaded program looks like {}".format(exec_fmt))


def to_ghidra_addr(offset, fmt, image_base, elf_original_base):
    # PE: unhusk's value is an RVA (relative to image base, by definition --
    # container/mod.rs), and Ghidra's PE loader places every section at
    # imageBase + RVA (PeLoader.java). image_base here is whatever Ghidra
    # actually loaded at -- correct even if Ghidra had to rebase off the
    # PE's own preferred ImageBase, since RVA is relative-to-load-base by
    # construction.
    #
    # ELF: unhusk's vaddr is the file's raw p_vaddr, which is only the same
    # number as Ghidra's loaded address if Ghidra used the file's own base
    # unchanged. It doesn't always: empirically (headless run against
    # bench/run1/build/kibi, an ordinary PIE Rust binary whose PT_LOAD
    # segments start at p_vaddr 0), Ghidra loaded it at image base
    # 0x100000, not 0 -- an x86-64-language default, not anything read from
    # the file. unhusk's raw 0x22010 is not a Ghidra address there; the
    # loaded one is 0x122010. Ghidra records the file's own original base
    # as a program property specifically to make this translation exact
    # (ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY) rather than assumed, so
    # this reads that back instead of guessing "loaded == file vaddr".
    if fmt == "pe":
        return image_base.add(offset)
    base = elf_original_base if elf_original_base is not None else 0
    return image_base.add(offset - base)


def fix_boundaries(data):
    fm = currentProgram.getFunctionManager()
    image_base = currentProgram.getImageBase()
    elf_original_base = ElfLoader.getElfOriginalImageBase(currentProgram)
    fmt = data.get("format", "")
    functions = data.get("functions", [])
    print("unhusk-ghidra: {} boundaries from {} ({})".format(
        len(functions), data.get("binary", "?"), fmt or "?"))
    if fmt == "elf":
        print("unhusk-ghidra: image_base={} elf_original_base={}".format(
            image_base, elf_original_base))

    matched = corrected = created = failed = 0

    for entry in sorted(functions, key=lambda e: int(e["start"], 16)):
        if monitor.isCancelled():
            break

        start = int(entry["start"], 16)
        end = int(entry["end"], 16)
        if end <= start:
            failed += 1
            print("unhusk-ghidra: skipping degenerate range 0x{:x}..0x{:x}".format(start, end))
            continue

        entry_addr = to_ghidra_addr(start, fmt, image_base, elf_original_base)
        last_addr = to_ghidra_addr(end - 1, fmt, image_base, elf_original_base)
        if entry_addr is None or last_addr is None:
            failed += 1
            print("unhusk-ghidra: could not resolve address for 0x{:x}..0x{:x}".format(start, end))
            continue
        target = AddressSet(entry_addr, last_addr)

        overlapping = list(fm.getFunctionsOverlapping(target))

        if (len(overlapping) == 1
                and overlapping[0].getEntryPoint() == entry_addr
                and overlapping[0].getBody().hasSameAddresses(target)):
            matched += 1
            continue

        # CreateFunctionCmd refuses a body that overlaps any existing
        # function, so every conflicting function -- a merged pair, a
        # missed start, a wrong split -- has to go before the exact body
        # unhusk names can be created in its place.
        was_empty = len(overlapping) == 0
        for f in overlapping:
            fm.removeFunction(f.getEntryPoint())

        cmd = CreateFunctionCmd(None, entry_addr, target, SourceType.ANALYSIS)
        if cmd.applyTo(currentProgram):
            if was_empty:
                created += 1
            else:
                corrected += 1
        else:
            failed += 1
            print("unhusk-ghidra: failed to create function at {}: {}".format(
                entry_addr, cmd.getStatusMsg()))

    total = len(functions)
    print("unhusk-ghidra: matched={} corrected={} created={} failed={} total={}".format(
        matched, corrected, created, failed, total))


data = load_boundaries()
check_format(data)
fix_boundaries(data)

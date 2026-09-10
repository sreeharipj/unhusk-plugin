# IDAPython port of ghidra_scripts/ApplyUnhusk.py.
#
# Not tested inside IDA -- written from the API docs (IDA 7.4+). Calls to
# verify are marked "# CHECK"; the Ghidra script is the tested reference.
#
# Marks each STRONG/SINGLE-tier function from unhusk's --json feed: a header
# comment with the tier, rule, and recovered source paths; a muted colour; and
# on IDA 7.5+ an unhusk/<tier> folder in the Functions window. It does not
# rename. Run FixBoundaries.py first so feed addresses hit real function
# starts.
#
# Run:  idat64 -A -L/tmp/au.log -S"ApplyUnhusk.py triage.json" target.i64
#   or  File > Script file... in the GUI.

import json

import ida_funcs
import ida_kernwin
import ida_nalt
import idc

try:
    import ida_ida

    def filetype():
        return ida_ida.inf_get_filetype()                     # CHECK: 7.4+ name
except ImportError:
    def filetype():
        return idc.get_inf_attr(idc.INF_FILETYPE)

try:
    import ida_dirtree                                        # folders: 7.5+, optional
except ImportError:
    ida_dirtree = None

MARKER = "unhusk:"
# IDA item colours are 0xBBGGRR.
TIER_COLOR = {"strong": 0xC8F0C8, "single": 0xC8E8F8}


def script_arg():
    argv = idc.ARGV
    if len(argv) > 1:
        return argv[1]
    path = ida_kernwin.ask_file(False, "*.json", "unhusk --json triage feed")
    if not path:
        raise SystemExit("ApplyUnhusk: no triage file given")
    return path


def to_ea(offset, fmt, image_base):
    return image_base + offset if fmt == "pe" else offset


def comment_block(fn, rule):
    n = fn.get("anchor_count", 0)
    lines = ["%s %s (%s, %d anchor%s)"
             % (MARKER, fn.get("tier", "?").upper(), rule, n, "" if n == 1 else "s")]
    lines += ["  " + p for p in fn.get("anchor_files", [])]
    return "\n".join(lines)


def merge_comment(ea, block):
    """Set the function comment to `block`, keeping any text that isn't a prior
    unhusk block, so re-runs are idempotent."""
    old = idc.get_func_cmt(ea, 0) or ""                       # 0 = header comment
    kept, skipping = [], False
    for line in old.split("\n"):
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
    kept_text = "\n".join(kept).strip("\n").strip()
    new = block if not kept_text else block + "\n\n" + kept_text
    if new != old:
        idc.set_func_cmt(ea, new, 0)                          # CHECK: (ea, cmt, repeatable)


def move_to_folder(func_ea, tier):
    if ida_dirtree is None:
        return
    try:
        dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
        dt.mkdir("unhusk")
        dt.mkdir("unhusk/" + tier)
        name = ida_funcs.get_func_name(func_ea)
        dt.rename(name, "unhusk/%s/%s" % (tier, name))        # CHECK: rename moves the entry
    except Exception:
        pass


def main():
    with open(script_arg(), "rb") as fp:
        data = json.loads(fp.read())
    fmt = data.get("format") or ("pe" if filetype() == idc.FT_PE else "elf")
    rule = data.get("rule", "?")
    image_base = ida_nalt.get_imagebase()
    funcs = data.get("functions", [])
    print("unhusk-plugin: %d triage functions from %s (rule %s, arch %s)"
          % (len(funcs), data.get("binary", "?"), rule, data.get("arch", "?")))

    annotated = at_container = no_function = 0

    for fn in sorted(funcs, key=lambda e: int(e["start"], 16)):
        want = to_ea(int(fn["start"], 16), fmt, image_base)
        f = ida_funcs.get_func(want)
        if f is None:
            no_function += 1
            print("unhusk-plugin: no function at %#x -- run FixBoundaries.py first" % want)
            continue
        anchor = f.start_ea
        if anchor != want:
            at_container += 1

        merge_comment(anchor, comment_block(fn, rule))
        try:
            idc.set_color(anchor, idc.CIC_FUNC,               # CHECK: CIC_FUNC + 0xBBGGRR
                          TIER_COLOR.get(fn.get("tier"), 0xFFFFFF))
        except Exception:
            pass
        move_to_folder(anchor, fn.get("tier", "other"))
        annotated += 1

    print("unhusk-plugin: annotated=%d, at-containing-function=%d, no-function=%d"
          % (annotated, at_container, no_function))
    if at_container or no_function:
        print("unhusk-plugin: run FixBoundaries.py first so addresses hit exact starts.")


main()

# ida_scripts — IDAPython port (trusted, not tested)

An IDAPython version of the three scripts in `../ghidra_scripts/`. Written
against the documented IDAPython API (IDA 7.4+). **It has not been run inside
IDA.** No IDA install was available when it was written; the Ghidra scripts are
the tested reference and their measurements (`../README.md`) do not
automatically carry over.

Calls that are version-sensitive, or that I could not verify against a running
IDA, are marked `# CHECK` in the source.

## Scripts

| script | does | needs |
|---|---|---|
| `FixBoundaries.py` | replace IDA's function extents with unhusk's `--boundaries` feed (unwind-table ground truth) | `unhusk <bin> --boundaries` |
| `ApplyUnhusk.py` | function comment + colour + `unhusk/<tier>` folder at each STRONG/SINGLE function | `unhusk <bin> --json`, run after `FixBoundaries.py` |
| `ExtractEdges.py` | `{location -> [function]}` map for `unhusk --tier-from`, from IDA's own xrefs | `unhusk <bin> --locations`, run after `FixBoundaries.py` |

## Run

```sh
unhusk sample.bin --boundaries > b.json
unhusk sample.bin --json        > t.json

idat64 -A -L/tmp/fb.log -S"FixBoundaries.py b.json" sample.bin   # makes sample.bin.i64
idat64 -A -L/tmp/au.log -S"ApplyUnhusk.py t.json"  sample.bin.i64
```

`-A` is autonomous (no dialogs), `-S"script arg…"` passes args (reachable as
`idc.ARGV`), `-L` is the log. In the GUI: File ▸ Script file… — each script
prompts for its JSON.

## What to verify before trusting it

- **Address translation.** `to_ea()` assumes IDA loads ELF segments at their
  `p_vaddr` unchanged (unlike Ghidra's 0x100000 x86-64 default) and loads PE at
  `get_imagebase() + RVA`. Confirm on one ELF and one PE; if the database was
  rebased, the ELF path needs `+ (current base − original base)`.
- **`ida_funcs.del_func` / `add_func(start, end)` / `set_func_end`.** That
  `add_func` with an explicit end does **not** auto-extend past it (the point of
  the script), and that `del_func` takes any address in the function.
- **`ida_bytes.del_items(ea, flags, nbytes)`** argument order and that
  `DELIT_SIMPLE` is the right flag.
- **`idc.get_func_cmt` / `set_func_cmt(ea, cmt, 0)`** — that `0` is the
  non-repeatable (header) comment and that it renders multi-line.
- **`idc.set_color(ea, CIC_FUNC, colour)`** — colour is `0xBBGGRR`, so the
  greens/ambers in `TIER_COLOR` may need swapping.
- **`ida_dirtree`** (folders) — 7.5+ only, wrapped in `try/except`; `rename`
  moving an entry into a path is the assumption. The script is correct without
  it.
- **`idautils.XrefsTo(ea, 0)`** in `ExtractEdges.py` — that IDA created data
  xrefs for RIP-relative loads into `.rodata`/`.rdata` during analysis, and how
  complete they are versus unhusk's own decode pass. This is the number that
  has to be re-measured, per architecture.
- **`ida_ida.inf_get_filetype` / `inf_is_64bit`** — 7.4+ names; older releases
  used `idaapi.get_inf_structure()`.

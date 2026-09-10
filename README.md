# unhusk-plugin

unhusk-plugin marks the author-written code in a stripped Rust binary, inside
Ghidra or IDA. It reads the JSON that [unhusk](https://github.com/sreeharipj/unhusk)
emits and writes function boundaries, comments, and bookmarks. It runs no
analysis of its own.

Two backends, three scripts each, same JSON:

- **`ghidra_scripts/`** — Jython. Drop into the Script Manager and run. This is
  the tested path.
- **`ida_scripts/`** — IDAPython 7.4+. Written against the documented API, not
  yet run inside IDA. See `ida_scripts/README.md`.

## Example

`kibi`, a small Rust terminal editor, stripped:

```console
$ unhusk kibi.stripped --boundaries > boundaries.json
$ unhusk kibi.stripped --json        > triage.json

$ analyzeHeadless proj kibi -import kibi.stripped \
    -scriptPath unhusk-plugin/ghidra_scripts \
    -postScript FixBoundaries.py boundaries.json \
    -postScript ApplyUnhusk.py   triage.json
...
unhusk-plugin: 796 boundaries from kibi.stripped (elf)
unhusk-plugin: matched=427 corrected=367 created=2 failed=0 total=796
unhusk-plugin: 9 triage functions from kibi.stripped (rule count@2, arch x86-64)
unhusk-plugin: annotated=9 (plate comments=9), at-containing-function=0, no-function=0
```

FixBoundaries.py corrected 367 boundaries Ghidra had wrong and created 2 it had
missed, out of 796. ApplyUnhusk.py then marked the 9 functions unhusk
attributes to author code, each on an exact function start.

In the listing, each one carries a plate comment:

```
             unhusk: STRONG (count@2, 6 anchors)
               src/editor.rs
               src/row.rs
             FUN_00127830
00127830 55  PUSH  RBP
...
```

and a bookmark under category `unhusk`, so Ctrl+B with the filter set to
`unhusk` lists all nine:

```
001276c0  [single] unhusk single tier | count@2 | 1 anchor(s) | src/editor.rs
00127830  [strong] unhusk strong tier | count@2 | 6 anchor(s) | src/editor.rs, src/row.rs
0012a390  [strong] unhusk strong tier | count@2 | 3 anchor(s) | src/editor.rs
0012c4c0  [strong] unhusk strong tier | count@2 | 3 anchor(s) | src/editor.rs
...
```

Nothing is renamed. A second run replaces its own comment block in place.

## The three scripts

**`FixBoundaries.py`** replaces the disassembler's function boundaries with
unhusk's. unhusk takes them from `.eh_frame` on ELF and `.pdata` on PE, which
the compiler keeps for stack unwinding and `strip` leaves alone. Against DWARF,
that gets start and end both byte-exact 99.9% of the time; angr's CFGFast gets
73.3%, Ghidra headless 62.9%. A disassembler infers the end from control flow
and stops early on a tail call or an unresolved jump table. Run this first.

**`ApplyUnhusk.py`** reads unhusk's `--json` feed and marks each author
function. In Ghidra that is a bookmark; in IDA, a folder and a colour. Both get
a header comment with the tier, the rule, and the recovered `src/` paths. It
never renames. A second run replaces its own comment block and leaves other
text alone.

**`ExtractEdges.py`** is optional. unhusk's own attribution scan is x86-64
only. This script hands that step to the disassembler: for each panic record it
collects the cross-references the disassembler already found and writes
`{record -> function}`. Feed that back with
`unhusk --json --tier-from edges.json`. unhusk still applies every ranking
rule; only the "which function" step changes. See [Status](#status) for what it
costs.

## Ghidra

Jython, because it ships in stock Ghidra with no install. Ghidra 12.x also
bundles PyGhidra (CPython 3), but that needs `pyghidraRun` and a working
Python-JVM bridge, and its script provider takes priority over unmarked `.py`
files — an unmarked script fails with "Ghidra was not started with PyGhidra"
even when you never asked for it. Each script carries a `#@runtime Jython` tag
to opt out.

The two-script path is in [Example](#example). For `--tier-from`, add a
`--locations` feed and one more script:

```sh
unhusk sample.bin --boundaries > boundaries.json
unhusk sample.bin --locations  > locations.json

analyzeHeadless <project> <name> -import sample.bin \
  -scriptPath /path/to/unhusk-plugin/ghidra_scripts \
  -postScript FixBoundaries.py boundaries.json \
  -postScript ExtractEdges.py  locations.json edges.json

unhusk sample.bin --json --tier-from edges.json > triage.json

analyzeHeadless <project> <name> -process sample.bin -noanalysis \
  -scriptPath /path/to/unhusk-plugin/ghidra_scripts \
  -postScript ApplyUnhusk.py triage.json
```

Scripts also run from the Script Manager on a loaded program; each prompts for
its JSON.

## IDA

`ida_scripts/` mirrors the three scripts against IDAPython 7.4+. It has not run
inside IDA yet. `ida_scripts/README.md` lists what to check first.

```sh
unhusk sample.bin --boundaries > b.json
unhusk sample.bin --json        > t.json

idat64 -A -L/tmp/fb.log -S"FixBoundaries.py b.json" sample.bin   # writes sample.bin.i64
idat64 -A -L/tmp/au.log -S"ApplyUnhusk.py t.json"  sample.bin.i64
```

## Address translation

Turning an unhusk address into a disassembler address is the one
format-specific step. An early version got ELF wrong, caught by running it
headless.

- **PE** — unhusk emits an RVA. Ghidra's loader puts each section at
  `imageBase + RVA`, so the script uses `getImageBase().add(rva)`. Verified
  against `dufs.stripped.exe`, 4132 functions.
- **ELF** — unhusk emits the file's `p_vaddr`. Ghidra does not always load
  there: `kibi.stripped` is a PIE with `p_vaddr` 0, and Ghidra loaded it at
  `0x100000` anyway, an x86-64 default. Every address was off by that much. The
  fix reads the original base back from `ElfLoader.getElfOriginalImageBase` and
  translates `imageBase.add(vaddr - originalBase)`. IDA loads ELF at `p_vaddr`
  unchanged, so the IDA script uses the vaddr directly — one of its `# CHECK`
  items.

Addresses are built with `Address.add(long)`, not by formatting to a hex string
and parsing it back: on Jython, `hex()` on a value above `0x7fffffff` appends
an `L` that Ghidra's address parser rejects.

## Status

`--boundaries`, `--locations`, and `--json --tier-from` all ship in unhusk.
Every measurement below is the Ghidra scripts; the IDA port is unmeasured.

### FixBoundaries.py

Headless, full pipeline: import, auto-analysis, script, re-analysis. "Before" is
stock Ghidra against unhusk's boundaries with no script run.

| binary | true fns | stock Ghidra | exact match, before | matched / corrected / created / failed | exact match, after |
|---|---|---|---|---|---|
| kibi.stripped (ELF) | 796 | 918 | 498/796 | 427 / 367 / 2 / 0 | 795/796 |
| dufs.stripped.exe (PE) | 4132 | 4473 | 3881/4132 | 2135 / 1995 / 0 / 2 | 4130/4132 |

Two known gaps, both left alone:

- **ELF, 1/796** — a 6-byte function was created correctly, then merged back by
  Ghidra's own Shared Return Calls analyzer in the re-analysis pass. A real
  function; Ghidra's downstream analysis undoes it, not this script.
- **PE, 2/4132** — two tiny `.pdata` ranges (2 and 6 bytes) sit on bytes Ghidra
  had already called data, so it refused to make functions there. Most likely
  `.pdata` padding, not real functions.

### ApplyUnhusk.py

On kibi, all 9 feed functions were annotated on exact starts: 0 fell back to a
containing function, 0 had no function. Re-runs are idempotent.

### ExtractEdges.py + --tier-from

Verified on kibi only: ELF, x86-64, 796 functions. It does not transfer to
other architectures without re-measuring.

- 291 records, 285 attributed, 365 edges, 6 with no function. 5 references
  pointed into the middle of a record rather than its first byte, caught
  because the scan covers the whole struct.
- Against unhusk's own scan, 282 of 291 records got the same function. The
  other 9 are code Ghidra never disassembled — jump tables — so there was no
  reference to follow. Not a wrong answer, a missing one.
- Tiers (`count@2`), 9 functions: after FixBoundaries, 7 unchanged, 2 dropped
  (`0x27f70` and `0x2a750`, both with unresolved jump tables), 0 promoted.
  Without FixBoundaries first, 3 dropped. It only ever under-reports.

## License

Apache-2.0. See `LICENSE`.

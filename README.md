# unhusk-ghidra

Ghidra integration for [unhusk](https://github.com/sreeharipj/unhusk), a
precision-first triage tool that recovers user-authored function boundaries
and their originating source paths from stripped Rust binaries (ELF and PE,
x86-64) via the `core::panic::Location` metadata compiler-emitted for every
panic site.

unhusk is the product; this repo is a thin consumer of its `--json` /
`--boundaries` output, in the same spirit as GoReSym's own Ghidra script
(`goresym_rename.py`) consumes GoReSym's JSON — no analysis logic is
duplicated here, only address bookkeeping inside the Ghidra API.

Written in Jython (Python 2.7), because that's what ships in stock Ghidra —
no extension install, drop the script into the Script Manager and run it.
(Ghidra 12.x also bundles PyGhidra/CPython 3, but that needs launching
through `pyghidraRun` with a working Python3↔JVM bridge; Jython is the
zero-setup path, which matters more here than the language version.)

One catch, found by actually running these headless rather than trusting
that description: Ghidra 12.x gives PyGhidra's script provider explicit
top priority (`@ExtensionPointProperties(priority = 1000)`,
`PyGhidraScriptProvider.java`) specifically so it wins any `.py` file that
doesn't say otherwise — an unmarked script fails with "Ghidra was not
started with PyGhidra" even though it was never run through `pyghidraRun`.
`FixBoundaries.py` (and `ApplyUnhusk.py`, when it lands) carries an
explicit `#@runtime Jython` header tag for exactly this reason; it's not
optional decoration.

## Two scripts, run in order

Ghidra's own function-start heuristics are unreliable on stripped,
optimized Rust code — merged functions, missed starts, tail-call and
jump-table confusion. unhusk already has *exact* function boundaries for
every function in the binary (not just the ones it can attribute to user
code), for free, because both formats carry them for unwinding and they
survive `strip --strip-all`:

- ELF: `.eh_frame` FDEs (`frame::parse_eh_frame`)
- PE: `.pdata` `RUNTIME_FUNCTION` entries (`container::pe::parse_pdata_ranges`)

unified behind one already-existing trait method,
`BinaryImage::function_ranges() -> Vec<Range<u64>>`.

**1. `FixBoundaries.py`** — reads unhusk's full boundary feed and makes
Ghidra's function model match it exactly: skip what's already correct,
force-create/re-split what isn't (explicit `AddressSetView` body, not
Ghidra's auto-follow, so it can't over/undershoot). Logs matched /
corrected / newly-created counts. Runs first, on every function in the
binary — this step has nothing to do with unhusk's panic-Location
triage specifically, it's a general fix.

**2. `ApplyUnhusk.py`** — reads unhusk's tiered triage feed (`--json`) and,
now that boundaries are trustworthy, adds a Bookmark (tier, rule,
anchor_count) and a plate comment (the recovered crate/file paths) at each
STRONG/SINGLE-tier function. No renaming by default — comment+bookmark
only, so it never overwrites a name already set.

Neither script hardcodes an architecture. Both only ever do
"read an address from JSON, act on it in the currently loaded program" —
Ghidra's addressing API is arch-neutral already. The `arch` field in
unhusk's JSON is used only as a soft mismatch warning (wrong file picked),
never a gate. unhusk itself staying x86-64-only (built on `iced-x86`, which
is x86/x64-only) is a fact about unhusk, not something either script
imposes.

## Usage

```sh
unhusk sample.bin --boundaries > sample.boundaries.json
unhusk sample.bin --json        > sample.triage.json
```

Load `sample.bin` in Ghidra, run `FixBoundaries.py` then `ApplyUnhusk.py`
from the Script Manager (each `askFile`-prompts for its JSON if not passed
as an arg), or headless:

```sh
analyzeHeadless <project> <name> -process sample.bin \
  -scriptPath /path/to/unhusk-ghidra/ghidra_scripts \
  -postScript FixBoundaries.py sample.boundaries.json \
  -postScript ApplyUnhusk.py   sample.triage.json
```

## Address translation

The one format-specific piece of `FixBoundaries.py` is turning unhusk's
addresses into Ghidra addresses, not instruction decoding — and the first
version of this section was wrong about ELF, caught only by actually
running the script headless rather than trusting a source-code read:

- **PE**: unhusk's value is an RVA (relative to image base, by definition).
  Ghidra's PE loader places every section at `imageBase + RVA`
  (`PeLoader.java`), so the script computes `currentProgram.getImageBase()
  .add(rva)`. Verified headless against `bench/hypotheses/v_pe/
  dufs.stripped.exe` (4132 functions): correct with no adjustment.
- **ELF**: unhusk's vaddr is the file's raw `p_vaddr`, which is only the
  same number as Ghidra's *loaded* address when Ghidra used the file's own
  base unchanged — and it doesn't always. Headless against `bench/run1/
  build/kibi/c3/kibi.stripped`, an ordinary PIE Rust binary whose `PT_LOAD`
  segments start at `p_vaddr 0`: Ghidra loaded it at image base `0x100000`
  anyway (an x86-64-language default, not anything the file specifies).
  Every one of unhusk's addresses was off by that same `0x100000` until
  this was caught. The fix reads the file's *original* base back from a
  property Ghidra itself records at import for exactly this kind of
  translation (`ElfLoader.ELF_ORIGINAL_IMAGE_BASE_PROPERTY`, exposed as
  `ElfLoader.getElfOriginalImageBase(currentProgram)`) instead of assuming
  "loaded == file vaddr": `image_base.add(unhusk_vaddr - original_base)`.

Both loader behaviors confirmed by reading `ElfProgramBuilder.java` /
`PeLoader.java` in a local Ghidra source clone, and both address formulas
confirmed against real, auto-analyzed programs, not just plausible-looking
source. Addresses are built with `Address.add(long)`, not a hex-string
round trip — the earlier draft of this section formatted addresses with
`hex()`/`toAddr(string)` and carried a documented Jython gotcha (`hex()`
on Jython's auto-promoted-to-`long` ints for any address above
`0x7fffffff` appends a trailing `"L"` that Ghidra's address parser
rejects); `Address.add(long)` has no string step to have that bug in.

## Status

`--boundaries` ships in unhusk (`--boundaries`, `container::print_boundaries`).

`FixBoundaries.py` is written and headless-verified on real corpus binaries,
both formats, full pipeline (import → auto-analysis → script → re-analysis):

| binary | functions | matched | corrected | created | failed | exact match after |
|---|---|---|---|---|---|---|
| kibi.stripped (ELF) | 796 | 427 | 367 | 2 | 0 | 795/796 |
| dufs.stripped.exe (PE) | 4132 | 2135 | 1995 | 0 | 2 | 4130/4132 |

Two known, minor gaps, both left as-is rather than engineered around for
a fraction-of-a-percent of cases:

- **ELF, 1/796**: a 6-byte function got created correctly, then absorbed
  by Ghidra's own *Shared Return Calls* analyzer during the post-script
  re-analysis pass (a shared-epilogue jump stub merged into its target).
  A real function per unhusk's ground truth; Ghidra's own downstream
  analysis, not this script, undoes it.
- **PE, 2/4132**: two adjacent tiny (2- and 6-byte) `.pdata` ranges landed
  on bytes Ghidra had already classified as defined data rather than code
  (`"Function entryPoint may not be created on defined data"`) — most
  likely alignment/padding entries in `.pdata` rather than real functions.

`ApplyUnhusk.py` is not started.

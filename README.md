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

## Status

Planning stage — `--boundaries` doesn't exist in unhusk yet (small addition:
serialize `BinaryImage::function_ranges()`, no new parsing needed), and
neither script is written yet. This file is the design record.

# Large-binary loading investigation

Local measurements on the supplied `vmlinux` (approximately 26 MiB), Python
3.14, Capstone 5.0.7. These are individual observations, not statistical benchmark
results. File reading may benefit from the OS page cache.

Opening/parsing the ELF and hashing it took about 0.057 seconds. The executable
LOAD segments contain 15,355,904 and 1,052,672 bytes. The apparent “loading” delay
mostly occurs after opening: gadget discovery, then sorting, cache serialization,
and filtering.

## Confirmed bottleneck and change

Both `_searchGadgetsSingle` and `__gatherGadgetsByEnding` previously searched a
suffix of the segment and replaced it with a new suffix after each match:

```python
tmp_code = tmp_code[index + arch.align:]
```

Each slice copies the remaining bytes. With a roughly constant density of
endings, cumulative copying grows quadratically with segment size. The largest
segment contains 62,116 `c3` matches; scanning just those matches copied about
688.6 GB cumulatively (not peak memory usage).

| Work measured | Before | After |
| --- | ---: | ---: |
| Find `c3` matches, no disassembly | 40.70 s | 0.012 s |
| Discover gadgets for `c3`, six-instruction limit, with cProfile | 71.96 s | 27.02 s |

The change compiles each ending regex once and searches the original buffer with
an advancing position. Candidate gadget slices remain small. It preserves the
previous lower bound for backward decoding, alignment, overlapping matches,
branch-delay handling, and progress reporting.

The profiled worker produced 503,666 gadgets both before and after, with identical
serialized output hashes. The complete CLI load was not timed; this 2.7x speedup
applies to one ending in one segment and excludes IPC, sorting, and cache work.
The matching-only measurement is not an end-to-end speedup.

Validation: all 31 existing tests passed. Exact serialized results also matched
the original implementation for single-process discovery and every ending's
worker on `ls-x86`, `ls-x86_64`, `ls-arm`, `ls-arm64`, `ls-mipsel`, and `ls-ppc`.

## Reproduce a worker measurement

From the repository root, with Capstone installed and the filebytes submodule
available:

```sh
PYTHONPATH=.:filebytes python benchmarks/scan_ending.py vmlinux --profile
ROPPER_CACHE=/tmp/ropper-test-cache PYTHONPATH=filebytes python test.py
```

The benchmark selects executable segment 0 and ROP ending 0 by default. Use
`--section`, `--ending`, and `--inst-count` to change them. Omit `--profile` for
wall-clock timing without profiler overhead. Run the same benchmark against each
revision to compare; compare output hashes as well as time. Its internal worker
API deliberately bypasses cache, sorting, filtering, and multiprocessing.

## Next improvements to investigate

1. **Gadget construction/disassembly.** After the fix, `__createGadget` accounts
   for 25.49 of 27.02 profiled seconds, across 850,417 candidate decodes. Investigate
   bounded decoding and reduced Capstone/Python object overhead. Preserve gadget
   completeness, variable-length instructions, and branch-delay behavior.
2. **Scheduling and progress.** Multiprocessing assigns whole ending patterns
   to workers. Common endings can dominate elapsed time, and progress advances
   only when a complete pattern returns. Segment chunks could balance work and
   improve progress feedback, but require carefully tested boundary handling.
3. **Warm-cache loading.** `service.py` writes compressed Python `repr` and reads
   it with `eval`; workers then send gadget objects through multiprocessing
   queues, and the parent sorts the results. Benchmark this separately before
   selecting a compact, versioned data format. The search fix does not accelerate
   cache hits.
4. **Memory and serialization.** One ending alone yields half a million Gadget
   objects. Measure peak memory, IPC, sorting, and cache-write time across the
   full service path before optimizing these stages.

For immediate scope reduction, `--type rop` excludes JOP/SYS patterns and a lower
`--inst-count` reduces decoding work, but both change which gadgets are returned.
The copying fix preserves existing results without requiring those tradeoffs.

## Balanced worker scheduling

A subsequent change replaces one task per ending pattern with batches of at most
512 matches. On this machine (20 available CPUs), the original scheduling reached
92.59% when 25 of 27 patterns had returned, leaving the expensive `ret` patterns
to finish on individual workers. Progress now counts completed batches; it is
still a work counter, not an estimate of remaining wall-clock time.

Workers inherit the complete segment buffer through fork. Tasks contain an ending
pattern and its search-position bounds, including the previous match's boundary.
This gives each task exclusive ownership of its matches while retaining all
backward-decoding context and forward branch-delay bytes. No fixed overlap bound,
segment copies per task, or extra deduplication are needed. This also preserves
multiplicity when `--all` is used. Results are transferred in bounded batches,
and workers are joined on completion or terminated on failure.

Fresh measurements without cProfile, comparing the suffix-copy fix alone with
balanced scheduling:

| Measurement | One task per pattern | Batches of 512 matches |
| --- | ---: | ---: |
| First LOAD scan, 718,622 gadgets | 12.70 s | 3.29 s |
| Second LOAD scan, 41,660 gadgets | 0.75 s | 0.34 s |
| CLI `--file vmlinux`, stdout discarded, fresh cache | 27.05 s | 17.45 s |

Both segments' complete output hashes match, including gadget addresses, bytes,
instruction text, and multiplicity, independent of worker arrival order. These
are single-run measurements; they are separate from the earlier profiled timings.
The CLI includes sorting, cache writing, filtering, and output formatting, so its
speedup is smaller than discovery alone. Warm-cache reads do not use this scanner.

Run the parallel scanner benchmark with:

```sh
PYTHONPATH=.:filebytes python benchmarks/scan_parallel.py vmlinux
```

For CLI comparisons, use a fresh `ROPPER_CACHE` directory for each invocation to
force discovery rather than a cache hit. Keep the same benchmark script when
comparing revisions. `scan_parallel.py` deliberately calls the internal parallel
scanner and bypasses cache and post-processing.

Validation includes the existing suite plus batch-boundary equivalence on x86-64,
ARM, Thumb, ARM64, MIPS and PPC, overlapping and misaligned matches, output
multiplicity, progress, empty input, and worker exception/cleanup behavior:
35 tests pass.

## Optional cache bypass

Use `--no-cache` to skip both reads and writes, including analysis-triggered writes:

```sh
./Ropper.py --file vmlinux --no-cache >/dev/null
```

The API equivalent is `RopperService({'cache': False})`. Existing cache files are
left alone. Caching remains enabled by default.

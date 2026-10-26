"""Time parallel gadget discovery, without cache, sorting or CLI output.

Run from the repository root:
    PYTHONPATH=.:filebytes python benchmarks/scan_parallel.py vmlinux
"""
import argparse
import gc
import hashlib
import multiprocessing
import time

from ropper import RopperService
from ropper.gadget import GadgetType
from ropper.rop import Ropper


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--inst-count', type=int, default=6)
    args = parser.parse_args()
    multiprocessing.set_start_method('fork', force=True)
    service = RopperService()
    service.addFile(args.binary)
    binary = service.files[0].loader

    for index, section in enumerate(binary.executableSections):
        start = time.perf_counter()
        last_report = [start]

        def progress(section, gadgets, fraction):
            now = time.perf_counter()
            if now - last_report[0] >= 1 or fraction == 1:
                print('  %.1f%% at %.3f s' % (100 * fraction, now - start), flush=True)
                last_report[0] = now

        gadgets = Ropper(progress)._searchGadgetsForked(
            section, binary, args.inst_count, GadgetType.ALL)
        print('Segment %d: %d bytes; %.3f s; %d gadgets' %
              (index, section.size, time.perf_counter() - start, len(gadgets)), flush=True)
        # Ignore nondeterministic worker arrival order, but preserve multiplicity
        # and include addresses, bytes, instruction text, and section identity.
        hashes = sorted(hashlib.sha256(repr(g).encode()).digest() for g in gadgets)
        digest = hashlib.sha256()
        for value in hashes:
            digest.update(value)
        print('Output SHA-256:', digest.hexdigest(), flush=True)
        del gadgets, hashes
        gc.collect()


if __name__ == '__main__':
    main()

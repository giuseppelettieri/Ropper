"""Measure one gadget-ending worker without cache, IPC, sorting or filtering.

Run from the repository root:
    PYTHONPATH=.:filebytes python benchmarks/scan_ending.py vmlinux
Use --profile for Python call statistics (adds timing overhead).
"""
import argparse
import cProfile
import hashlib
import pstats
import time

from ropper import RopperService
from ropper.gadget import GadgetType
from ropper.rop import Ropper


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--section', type=int, default=0)
    parser.add_argument('--ending', type=int, default=0,
                        help='Index in the architecture ROP ending list')
    parser.add_argument('--inst-count', type=int, default=6)
    parser.add_argument('--profile', action='store_true')
    args = parser.parse_args()

    service = RopperService()
    start = time.perf_counter()
    service.addFile(args.binary)
    print('Open binary: %.3f s' % (time.perf_counter() - start), flush=True)
    binary = service.files[0].loader
    section = binary.executableSections[args.section]
    code = bytes(section.bytes)
    ending = binary.arch.endings[GadgetType.ROP][args.ending]
    offset = section.virtualAddress - binary.originalImageBase
    print('Architecture: %s; segment bytes: %d; ending: %r' %
          (binary.arch, len(code), ending), flush=True)

    profile = cProfile.Profile() if args.profile else None
    start = time.perf_counter()
    if profile:
        profile.enable()
    gadgets = Ropper()._Ropper__gatherGadgetsByEnding(
        code, binary.arch, binary.checksum, section.name, offset,
        ending, args.inst_count)
    if profile:
        profile.disable()
    print('Scan: %.3f s; gadgets: %d' %
          (time.perf_counter() - start, len(gadgets)), flush=True)
    print('Output SHA-256:', hashlib.sha256(repr(gadgets).encode()).hexdigest())
    if profile:
        pstats.Stats(profile).sort_stats('tottime').print_stats(15)


if __name__ == '__main__':
    main()

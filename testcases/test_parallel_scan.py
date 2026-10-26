import multiprocessing
import os
import random
import unittest
from collections import Counter

from ropper import RopperService
from ropper.arch import x86_64, ARM, ARMTHUMB, ARM64, MIPS, PPC
from ropper.common.error import RopperError
from ropper.gadget import GadgetType
from ropper.rop import Ropper


class SmallBatchRopper(Ropper):
    def _gadgetSearchTasks(self, code, arch, gtype, batch_size=3):
        return super(SmallBatchRopper, self)._gadgetSearchTasks(
            code, arch, gtype, batch_size)


class FailingRopper(SmallBatchRopper):
    def _Ropper__gatherGadgetsByEnding(self, *args, **kwargs):
        raise ValueError('worker failure')


class ParallelScanTests(unittest.TestCase):
    def test_batches_preserve_matches_and_backward_context(self):
        scanner = Ropper()
        rng = random.Random(42)
        # Include overlapping x86 endings and misaligned fixed-width endings.
        for arch, ending_bytes in ((x86_64, b'\xc2\xc2\xc2\xc3'),
                                   (ARM, b'\x10\xff\x2f\xe1'),
                                   (ARMTHUMB, b'\x00\xbd'),
                                   (ARM64, b'\xc0\x03\x5f\xd6'),
                                   (MIPS, b'\x09\xf8\x20\x03'),
                                   (PPC, b'\x4e\x80\x00\x20')):
            code = b''.join(bytes(bytearray(rng.randrange(256) for _ in range(n)))
                            + ending_bytes for n in range(32))
            for batch_size in (1, 3, 7):
                with self.subTest(arch=str(arch), batch_size=batch_size):
                    expected = []
                    for ending in arch.endings[GadgetType.ALL]:
                        expected.extend(scanner._Ropper__gatherGadgetsByEnding(
                            code, arch, 'test', 'code', 0x1000, ending, 6))
                    actual = []
                    for ending, start, end in scanner._gadgetSearchTasks(
                            code, arch, GadgetType.ALL, batch_size):
                        actual.extend(scanner._Ropper__gatherGadgetsByEnding(
                            code, arch, 'test', 'code', 0x1000, ending, 6, start, end))
                    # Includes multiplicity and ordering, not just unique gadgets.
                    self.assertEqual(repr(expected), repr(actual))

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires fork')
    def test_forked_results_progress_and_cleanup(self):
        service = RopperService()
        service.addFile('batch-test', bytes=b'\x90\x58\xc3' * 20,
                        raw=True, arch='x86_64')
        binary = service.files[0].loader
        expected = Ropper()._Ropper__gatherGadgetsByEnding(
            bytes(binary.executableSections[0].bytes), binary.arch,
            binary.checksum, binary.executableSections[0].name, 0,
            binary.arch.endings[GadgetType.ROP][0], 6)
        progress = []
        children = {p.pid for p in multiprocessing.active_children()}
        actual = SmallBatchRopper(lambda section, gadgets, value: progress.append(value)
                                 ).searchGadgets(binary, 6, GadgetType.ROP, True)
        self.assertEqual(Counter(map(repr, expected)), Counter(map(repr, actual)))
        self.assertGreater(len(progress), 4)
        self.assertEqual(progress, sorted(progress))
        self.assertEqual(progress[-1], 1.0)
        self.assertEqual(children, {p.pid for p in multiprocessing.active_children()})

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires fork')
    def test_worker_exception_is_reported_and_workers_reaped(self):
        service = RopperService()
        service.addFile('batch-test', bytes=b'\x90\xc3' * 20,
                        raw=True, arch='x86_64')
        children = {p.pid for p in multiprocessing.active_children()}
        with self.assertRaisesRegex(RopperError, 'worker failure'):
            FailingRopper().searchGadgets(service.files[0].loader, 6, GadgetType.ROP, True)
        self.assertEqual(children, {p.pid for p in multiprocessing.active_children()})

    def test_empty_tasks(self):
        self.assertEqual(list(Ropper()._gadgetSearchTasks(b'', x86_64, GadgetType.ALL)), [])
        self.assertEqual(list(Ropper()._gadgetSearchTasks(b'\x90' * 20, x86_64, GadgetType.ALL)), [])

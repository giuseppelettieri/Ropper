import os
import tempfile
import unittest
from unittest.mock import patch

from ropper.gadget import Gadget
from ropper.service import RopperService


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='ropper-cache-test-')
        self.addCleanup(self.directory.cleanup)
        folder = patch.object(RopperService, 'CACHE_FOLDER', self.directory.name)
        folder.start()
        self.addCleanup(folder.stop)
        self.service = RopperService({})
        self.service.addFile('cache-test', bytes=b'\xc3', raw=True, arch='x86_64')
        self.file = self.service.files[0]

    def populate(self, count):
        gadgets = []
        for address in range(count):
            gadget = Gadget(self.file.loader.checksum, 'raw', self.file.arch)
            gadget.append(address, 'ret', bytes=b'\xc3')
            gadgets.append(gadget)
        self.file.allGadgets = gadgets

    def cache_path(self):
        return os.path.join(self.directory.name,
                            self.service._RopperService__getCacheFileName(self.file))

    def test_disabled_cache_ignores_existing_files_and_does_not_write(self):
        self.populate(12)
        self.service._RopperService__saveCache(self.file)
        with open(self.cache_path(), 'rb') as f:
            original = f.read()
        self.service.options.cache = False
        with patch.object(self.service, '_RopperService__getCacheFileName',
                          side_effect=AssertionError('cache path accessed')) as path_lookup, \
             patch('ropper.service.encode',
                   side_effect=AssertionError('cache serialization attempted')) as serializer:
            self.service.loadGadgetsFor()
        path_lookup.assert_not_called()
        serializer.assert_not_called()
        self.assertEqual(len(self.file.allGadgets), 1)
        with open(self.cache_path(), 'rb') as f:
            self.assertEqual(f.read(), original)
        unused = os.path.join(self.directory.name, 'unused')
        with patch.object(RopperService, 'CACHE_FOLDER', unused):
            self.service.loadGadgetsFor()
        self.assertFalse(os.path.exists(unused))

    def test_cache_options(self):
        from ropper.options import Options as CommandLineOptions
        self.assertTrue(RopperService({}).options.cache)
        self.assertFalse(RopperService({'cache': False}).options.cache)
        with self.assertRaises(TypeError):
            RopperService({'cache': 'false'})
        self.assertTrue(CommandLineOptions(['--file', 'example']).ropper_options['cache'])
        self.assertFalse(CommandLineOptions(['--file', 'example', '--no-cache']).ropper_options['cache'])

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires fork')
    def test_parallel_cache_read_does_not_change_global_start_method(self):
        self.populate(1105)
        self.service._RopperService__saveCache(self.file)
        with patch('ropper.service.multiprocessing.set_start_method',
                   side_effect=AssertionError('global start method changed')), \
             patch('ropper.service.multiprocessing.cpu_count', return_value=2):
            loaded = self.service._RopperService__loadCache(self.file)
        self.assertEqual(sorted(map(repr, loaded)), sorted(map(repr, self.file.allGadgets)))

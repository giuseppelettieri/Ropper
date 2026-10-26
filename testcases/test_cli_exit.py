import os
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from ropper.__main__ import _fast_exit


class CliExitTests(unittest.TestCase):
    def run_child(self, code, command='quit\n'):
        return subprocess.run([sys.executable, '-c', code], input=command,
                              text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=15)

    def test_standalone_entry_points_flush_and_skip_finalization(self):
        entry_points = (
            "runpy.run_path('Ropper.py', run_name='__main__')",
            "runpy.run_module('ropper', run_name='__main__')",
            "from ropper.__main__ import main; main()",
        )
        for entry in entry_points:
            for command in ('quit\n', ''):
                with self.subTest(entry=entry, command=command):
                    code = """
import atexit, runpy, sys
atexit.register(lambda: print('NORMAL FINALIZATION'))
print('BUFFERED STDOUT', end='')
print('BUFFERED STDERR', end='', file=sys.stderr)
sys.argv = ['ropper', '--console', '--no-load', '--nocolor']
""" + entry
                    result = self.run_child(code, command)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn('BUFFERED STDOUT', result.stdout)
                    self.assertIn('BUFFERED STDERR', result.stderr)
                    self.assertIn('(ropper)>', result.stdout)
                    self.assertNotIn('NORMAL FINALIZATION', result.stdout)

    def test_embedded_start_keeps_normal_exit_semantics(self):
        result = self.run_child("""
import atexit, ropper
atexit.register(lambda: print('NORMAL FINALIZATION'))
try:
    ropper.start(['--console', '--no-load', '--nocolor'])
except SystemExit as error:
    print('EMBEDDED EXIT', error.code)
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('EMBEDDED EXIT 0', result.stdout)
        self.assertIn('NORMAL FINALIZATION', result.stdout)

    def test_cli_errors_preserve_status_and_normal_cleanup(self):
        result = self.run_child("""
import atexit, sys
from ropper.__main__ import main
atexit.register(lambda: print('NORMAL FINALIZATION'))
sys.argv = ['ropper', '--not-a-valid-option']
main()
""")
        self.assertEqual(result.returncode, 2)
        self.assertIn('NORMAL FINALIZATION', result.stdout)

    @unittest.skipUnless(hasattr(os, 'fork'), 'requires fork')
    def test_fast_exit_stops_and_reaps_active_workers(self):
        result = self.run_child("""
import multiprocessing, time
from ropper.__main__ import _fast_exit
worker = multiprocessing.get_context('fork').Process(target=time.sleep, args=(60,))
worker.start()
print(worker.pid)
_fast_exit()
""")
        self.assertEqual(result.returncode, 0, result.stderr)
        pid = int(result.stdout.strip())
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_unresponsive_worker_falls_back_to_normal_exit(self):
        worker = Mock()
        worker.is_alive.return_value = True
        with patch('ropper.__main__.multiprocessing.active_children', return_value=[worker]), \
             patch('ropper.__main__.os._exit') as fast_exit:
            with self.assertRaises(SystemExit) as error:
                _fast_exit()
        self.assertEqual(error.exception.code, 0)
        worker.terminate.assert_called_once_with()
        worker.join.assert_called_once_with(timeout=1.0)
        fast_exit.assert_not_called()

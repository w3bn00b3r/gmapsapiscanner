"""Offline regression checks; no Google requests or billable API calls."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

import maps_api_scanner as scanner


class Response:
    def __init__(self, success=False):
        self.status_code = 200 if success else 403
        self.text = json.dumps({'routes': [], 'status': 'OK'} if success else {
            'error_message': 'denied', 'errorMessage': 'denied', 'error': {'message': 'denied'}})
        self.content = self.text.encode()
    def json(self):
        return json.loads(self.text)
    def iter_lines(self):
        return self.content.splitlines()


class CliUpdateTests(unittest.TestCase):
    def run_scan(self, filtered=False, mixed=False, **kwargs):
        calls = []
        def response(url, **kw):
            calls.append((url, kw))
            return Response(mixed and ('staticmap?' in url or ':computeRoutes?' in url))
        out = io.StringIO()
        with patch.object(scanner._ResultTable, 'export', return_value=True), patch.object(scanner.requests, 'get', side_effect=response), patch.object(scanner.requests, 'post', side_effect=response), contextlib.redirect_stdout(out):
            scanner.scan_gmaps('TEST_KEY', skip_jsapi=kwargs.pop('skip_jsapi', True), vulnerable_only=filtered, **kwargs)
        return out.getvalue(), calls

    def test_filtered_scan_preserves_requests_and_positive_results(self):
        normal, calls = self.run_scan(mixed=True)
        filtered, filtered_calls = self.run_scan(filtered=True, mixed=True)
        self.assertEqual(calls, filtered_calls)
        self.assertEqual(len(calls), 25)
        self.assertIn('not vulnerable', normal)
        self.assertNotIn('not vulnerable', filtered)
        self.assertNotIn('Reason:', filtered)
        self.assertRegex(filtered, r'\| 1 +\| Staticmap API +\| vulnerable +\| \$2 per 1000 requests +\| https://')
        self.assertIn('Routes API', filtered)
        self.assertIn('API-Type', filtered)
        self.assertIn('Status', filtered)
        self.assertIn('POC', filtered)
        self.assertNotIn('API key is', filtered)
        self.assertIn('curl ', filtered)
        self.assertIn('Cost Table', filtered)

    def test_no_findings_summary(self):
        output, _ = self.run_scan(filtered=True)
        self.assertIn('No vulnerable APIs detected', output)
        self.assertNotIn('Reason:', output)
        self.assertNotIn('not vulnerable', output)

    def test_cli_combinations(self):
        for argv in [
            ['app', '--vulnerable', '-a', 'KEY', '--no-jsapi', '-p', 'http://localhost:8080'],
            ['app', '--api-key', 'KEY', '--proxy', 'http://localhost:8080', '--no-jsapi', '--vulnerable'],
        ]:
            with patch.object(sys, 'argv', argv), patch.object(scanner, 'scan_gmaps') as scan, contextlib.redirect_stdout(io.StringIO()):
                scanner.main()
                scan.assert_called_once_with('KEY', skip_jsapi=True, proxy='http://localhost:8080', vulnerable_only=True, no_animation=False)

    def test_prompted_key(self):
        with patch.object(sys, 'argv', ['app', '--vulnerable']), patch('builtins.input', return_value='KEY'), patch.object(scanner, 'scan_gmaps') as scan:
            scanner.main()
            scan.assert_called_once_with('KEY', skip_jsapi=False, proxy=None, vulnerable_only=True, no_animation=False)

    def test_manual_javascript_file_lifecycle(self):
        with tempfile.TemporaryDirectory() as folder:
            previous = os.getcwd()
            os.chdir(folder)
            def answer(prompt):
                if prompt.startswith('Do you'):
                    return 'Y'
                self.assertIn('key=TEST_KEY', Path('jsapi_test.html').read_text())
                return ''
            try:
                with patch('builtins.input', side_effect=answer):
                    self.run_scan(filtered=True, skip_jsapi=False)
                self.assertFalse(Path('jsapi_test.html').exists())
            finally:
                os.chdir(previous)

    def test_plain_redirect_and_no_color(self):
        output, _ = self.run_scan(mixed=True)
        self.assertNotIn('\033[', output)
        with patch.dict(os.environ, {'NO_COLOR': '1'}), patch.object(sys.stdout, 'isatty', return_value=True):
            self.assertFalse(scanner._color_enabled())

    def test_colored_output(self):
        out = io.StringIO()
        with patch.object(scanner, '_color_enabled', return_value=True), contextlib.redirect_stdout(out):
            scanner._console_print('API key is vulnerable for Test API!')
        self.assertIn('\033[1;31m', out.getvalue())

    def test_posix_poc_quotes_json(self):
        with patch.object(scanner.os, 'name', 'posix'):
            command = scanner._curl_poc('https://example.test/?key=KEY', '{"test": "two words"}', {'Content-Type': 'application/json'})
        args = shlex.split(command)
        self.assertEqual(args[args.index('--data-binary') + 1], '{"test": "two words"}')

    def test_legacy_console_converts_ansi_to_win32(self):
        from colorama.ansitowin32 import AnsiToWin32
        out = io.StringIO()
        with patch('colorama.ansitowin32.winterm') as win32:
            converter = AnsiToWin32(out, convert=True, strip=True)
            with patch.object(scanner, 'just_fix_windows_console'), patch.object(scanner, '_color_enabled', return_value=True), patch.object(sys, 'stdout', converter.stream):
                scanner._console_print('API key is vulnerable for Test API!')
            self.assertNotIn('\033[', out.getvalue())
            self.assertIn('vulnerable for Test API', out.getvalue())
            win32.fore.assert_called()
            win32.reset_all.assert_called()

    def test_cmd_poc_quotes_url_with_ampersand(self):
        with patch.object(scanner.os, 'name', 'nt'):
            command = scanner._curl_poc('https://example.test/?a=1&key=KEY', '{}', {})
        self.assertIn('"https://example.test/?a=1&key=KEY"', command)

    def test_table_wraps_to_terminal_and_preserves_url(self):
        out = io.StringIO()
        url = 'https://example.test/?key=' + 'A' * 140
        table = scanner._ResultTable()
        table.add('Routes API (computeRouteMatrix)', 'vulnerable', url)
        with patch.object(scanner.shutil, 'get_terminal_size', return_value=os.terminal_size((80, 24))), contextlib.redirect_stdout(out):
            table.render()
        lines = out.getvalue().splitlines()
        self.assertTrue(all(len(line) <= 80 for line in lines))
        data_lines = [line for line in lines if line.startswith('|')][1:]
        reconstructed = ''.join(line.split('|')[5].strip() for line in data_lines)
        self.assertEqual(reconstructed, url)

    def test_animation_advances_and_stops(self):
        import threading
        out = io.StringIO()
        advanced = threading.Event()
        with patch.dict(os.environ, {'TERM': 'xterm'}), patch.object(out, 'isatty', return_value=True), patch.object(scanner, '_color_enabled', return_value=False), contextlib.redirect_stdout(out):
            animation = scanner._ScanAnimation()
            original = animation._write_frame
            def frame(index):
                original(index)
                if index > 0:
                    advanced.set()
            animation._write_frame = frame
            with animation:
                self.assertTrue(advanced.wait(2))
            self.assertIsNone(animation.thread)
        self.assertIn('Scanning...', out.getvalue())
        self.assertIn('sCanning...', out.getvalue())
        self.assertTrue(out.getvalue().endswith('\r' + ' ' * 11 + '\r'))

    def test_scan_exception_stops_animation(self):
        out = io.StringIO()
        with patch.dict(os.environ, {'TERM': 'xterm'}), patch.object(out, 'isatty', return_value=True), patch.object(scanner, '_color_enabled', return_value=False), contextlib.redirect_stdout(out), patch.object(scanner.requests, 'get', side_effect=RuntimeError('offline')):
            with self.assertRaisesRegex(RuntimeError, 'offline'):
                scanner.scan_gmaps('TEST', skip_jsapi=True)
        self.assertTrue(out.getvalue().endswith('\r' + ' ' * 11 + '\r'))

    def test_no_animation_in_redirected_output(self):
        output, _ = self.run_scan()
        self.assertNotIn('Scanning...', output)
        self.assertNotIn('\r', output)

    def test_new_cli_flags(self):
        with patch.object(sys, 'argv', ['app', '-a', 'KEY', '--no-animation']), patch.object(scanner, 'scan_gmaps') as scan:
            scanner.main()
        scan.assert_called_once_with('KEY', skip_jsapi=False, proxy=None, vulnerable_only=False, no_animation=True)

    def test_windows_poc_uses_native_curl(self):
        with patch.object(scanner.os, 'name', 'nt'):
            command = scanner._curl_poc('https://example.test', '{}', {})
        self.assertIn('Command Prompt (cmd.exe):\ncurl.exe ', command)
        self.assertIn('Windows PowerShell 3.0+:\ncurl.exe --% ', command)


if __name__ == '__main__':
    unittest.main()

import contextlib
import csv
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import maps_api_scanner as scanner
from tests.test_cli_update import Response


class ExportTests(unittest.TestCase):
    def test_scan_automatically_exports_complete_matching_records(self):
        for filtered in (False, True):
            with self.subTest(filtered=filtered), tempfile.TemporaryDirectory() as directory:
                previous = os.getcwd()
                try:
                    os.chdir(directory)
                    def response(url, **kwargs):
                        return Response('staticmap?' in url or ':computeRoutes?' in url)
                    with patch.object(scanner.requests, 'get', side_effect=response), patch.object(scanner.requests, 'post', side_effect=response), contextlib.redirect_stdout(io.StringIO()):
                        self.assertTrue(scanner.scan_gmaps('TEST_KEY', skip_jsapi=True, vulnerable_only=filtered))
                    files = list(Path('exports').glob('*'))
                    self.assertEqual(len(files), 2)
                    data = json.loads(next(Path('exports').glob('*.json')).read_text())
                    with next(Path('exports').glob('*.csv')).open(encoding='utf-8-sig', newline='') as f:
                        csv_data = list(csv.DictReader(f))
                    self.assertEqual(len(data), 2 if filtered else 25)
                    for row, csv_row in zip(data, csv_data):
                        self.assertEqual({k:str(v) for k,v in row.items()}, csv_row)
                    self.assertIn('key=TEST_KEY', data[0]['poc'])
                    self.assertEqual(data[0]['cost_table'], '$2 per 1000 requests')
                finally:
                    os.chdir(previous)

    def test_empty_exports_and_unique_names(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(scanner.Path, 'cwd', return_value=Path(directory)), contextlib.redirect_stdout(io.StringIO()):
            table = scanner._ResultTable(True)
            self.assertTrue(table.export())
            self.assertTrue(table.export())
            self.assertEqual(len(list(Path(directory).rglob('*.*'))), 4)
            for p in Path(directory).rglob('*.json'):
                self.assertEqual(json.loads(p.read_text()), [])
            for p in Path(directory).rglob('*.csv'):
                with p.open(encoding='utf-8-sig', newline='') as f:
                    self.assertEqual(list(csv.reader(f)), [['id', 'api_type', 'status', 'cost_table', 'poc']])

    def test_multiline_pocs_and_cost_variants_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(scanner.Path, 'cwd', return_value=Path(directory)), contextlib.redirect_stdout(io.StringIO()):
            table = scanner._ResultTable()
            poc = 'CMD:\ncurl.exe -d "{\\"x\\":1}"\nPowerShell:\nUnicode: café'
            table.add('Directions API', 'vulnerable', poc)
            self.assertTrue(table.export())
            data = json.loads(next(Path(directory).rglob('*.json')).read_text())
            self.assertEqual(data[0]['poc'], poc)
            self.assertIn('Directions (Advanced): $10 per 1000 requests', data[0]['cost_table'])
            with next(Path(directory).rglob('*.csv')).open(encoding='utf-8-sig', newline='') as f:
                self.assertEqual(next(csv.DictReader(f))['poc'], poc)

    def test_export_failure_is_reported(self):
        output = io.StringIO()
        with patch.object(scanner.Path, 'mkdir', side_effect=PermissionError('read only')), contextlib.redirect_stdout(output):
            self.assertFalse(scanner._ResultTable().export())
        self.assertIn('Export failed:', output.getvalue())

    def test_removed_option_rejected_and_no_separate_cost_table(self):
        with patch.object(scanner.sys, 'argv', ['scanner', '-a', 'KEY', '--wide-table']), patch.object(scanner, 'scan_gmaps') as scan, contextlib.redirect_stdout(io.StringIO()) as output:
            scanner.main()
        scan.assert_not_called()
        self.assertNotIn('--wide-table', output.getvalue())
        table = scanner._ResultTable()
        table.add('Staticmap API', 'vulnerable', 'https://example.test')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            table.render()
        self.assertIn('Cost Table', output.getvalue())
        self.assertNotIn('Tip:', output.getvalue())
        self.assertNotIn('Cost Table/Reference', output.getvalue())


if __name__ == '__main__':
    unittest.main()

# CLI update v1.4.1

## Install and run

Python 3.10+ is required. Extract this archive and open a terminal in its folder.
Windows CMD / PowerShell:

```cmd
py -m pip install -r requirements.txt
py maps_api_scanner.py --api-key "YOUR_KEY" --vulnerable --no-jsapi
```

Use python if the py launcher is unavailable. Linux/macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python maps_api_scanner.py --api-key "YOUR_KEY" --vulnerable --no-jsapi
```

## Single results table

Columns: # | API-Type | Status | Cost Table | POC.
Existing cost/reference text is attached to each API, including Advanced and
Per Session variants. The separate cost table is removed. Existing price strings
are retained from upstream, not refreshed or presented as actual charges.
Pricing reference links remain below the table.

The table wraps automatically (minimum terminal width: 80 columns). Full PoCs
are available in the exported files. The former wide-table option and tip are
removed. Colors and the dancing Scanning... animation are retained.

## Automatic JSON and CSV exports

After automated checks finish, every scan writes two files in the exports folder
under the directory from which you launched the command. No export flag is needed.
The absolute paths are printed after the results table.

File pattern: gmaps_scan_<UTC date/time with microseconds>Z_<unique suffix>.json
and the same basename with .csv. Runs do not overwrite earlier exports.

Both files contain id, api_type, status, cost_table, and poc fields. JSON is an
array of records. CSV uses UTF-8 with a BOM for Excel and proper quoting for commas,
quotes, and multiline values. Values retain full PoCs, API keys, reasons, and cost
variants without terminal color codes or display wrapping.

With --vulnerable, only vulnerable rows are displayed and exported. Without it,
all checked results are exported. No findings produces an empty JSON array and a
CSV header row. A file-write failure prints an Export failed message and attempts
to clean up incomplete files from that pair. Help does not create exports.

Exports cover completed automated checks, before the optional manual JavaScript
test. An interrupted scan or request exception does not produce completed-scan
exports; network-error continuation is not part of this update.

## Existing options

- --api-key / -a: supply the key; otherwise it is prompted for.
- --proxy / -p: proxy URL.
- --vulnerable: show and export only vulnerable results.
- --no-jsapi: skip the manual JavaScript test.
- --no-animation: disable the dancing letters.
- --help / -h: show usage.

Legacy CMD and Windows PowerShell color handling uses Colorama. Animation uses
ASCII text and carriage returns and disables itself for redirected output or
TERM=dumb. NO_COLOR disables colors. Separate CMD and PowerShell PoCs remain.

## Verification

33 tests passed, 1 upstream test skipped; 2 parameterized subtests passed.
Coverage includes real automatic export writes from simulated scans, filtered and
full exports, JSON/CSV content parity, multiline/Unicode values, empty results,
unique filenames, permission-error reporting, removed-option rejection, table
layout, and prior animation/CLI behavior. Tests run on Linux with mocked API
responses; native Windows/macOS and live Google API checks were not performed.

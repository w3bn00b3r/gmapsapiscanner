# Google Maps API Scanner

Test a Google API key against supported endpoints and review the results, cost references, and proof-of-concept requests in one table.

Based on [Ozgur Alp’s Google Maps API Scanner](https://github.com/ozguralp/gmapsapiscanner), with updated terminal output and automatic exports.

## Features

- Colorful CLI output with legacy Windows CMD and PowerShell handling.
- One results table: **# → API-Type → Status → Cost Table → POC**.
- `--vulnerable` to display and export only vulnerable results.
- Automatic JSON and CSV exports—no export flag required.
- HTTP and HTTPS proxy support, with SOCKS support when PySocks is installed.
- Optional manual JavaScript API check.

## Installation

Requires **Python 3.10+** and an internet connection.

### Install with pipx

With pipx installed:

```sh
pipx install git+https://github.com/w3bn00b3r/gmapsapiscanner.git
```

Run directly using the installed command:

```sh
gmapsapiscanner --api-key "YOUR_KEY" --vulnerable --no-jsapi
```

For SOCKS proxy support:

```sh
pipx inject gmapsapiscanner PySocks
```

Upgrade later:

```sh
pipx upgrade gmapsapiscanner
```

### Install from source

Clone the repository:

```sh
git clone https://github.com/w3bn00b3r/gmapsapiscanner.git
cd gmapsapiscanner
```

#### Windows — CMD or PowerShell

These commands use the virtual environment directly, without requiring shell activation:

```cmd
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe maps_api_scanner.py --api-key "YOUR_KEY" --vulnerable --no-jsapi
```

If the `py` launcher is unavailable, use `python` to create the environment.

#### Linux and macOS

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python maps_api_scanner.py --api-key "YOUR_KEY" --vulnerable --no-jsapi
```

Legacy terminal support does not guarantee compatibility with older Windows versions that cannot run the required Python version.

## Usage

For pipx installations, use `gmapsapiscanner`. For source installations, use your virtual environment’s Python executable followed by `maps_api_scanner.py`.

### Show only vulnerable results

```sh
gmapsapiscanner --api-key "YOUR_KEY" --vulnerable --no-jsapi
```

From source:

```sh
python maps_api_scanner.py --api-key "YOUR_KEY" --vulnerable --no-jsapi
```

### Prompt for the API key

```sh
gmapsapiscanner --vulnerable --no-jsapi
```

### Use a proxy

```sh
gmapsapiscanner --api-key "YOUR_KEY" --proxy "http://127.0.0.1:8080" --vulnerable --no-jsapi
```

### Options

| Option | Description |
| --- | --- |
| `--api-key KEY`, `-a KEY` | API key to test. Prompts when omitted. |
| `--proxy URL`, `-p URL` | HTTP, HTTPS, or SOCKS proxy. SOCKS requires PySocks. |
| `--vulnerable` | Display and export only vulnerable results. All checks still run. |
| `--no-jsapi` | Skip the interactive JavaScript API check. |
| `--no-animation` | Disable the animated scanning indicator. |
| `--help`, `-h` | Display usage information. |

## Results

Illustrative output:

| # | API-Type | Status | Cost Table | POC |
| --- | --- | --- | --- | --- |
| 1 | Staticmap API | vulnerable | $2 per 1000 requests | `https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=YOUR_KEY` |
| 2 | Routes API (computeRouteMatrix) | not vulnerable | Paid per element | Reason returned by the API |

Long values wrap in the terminal. Exported files preserve complete, unwrapped PoCs.

The **Cost Table** column retains upstream reference values; it is not a live pricing lookup or an estimate of your bill.

Colors are disabled for redirected output or when `NO_COLOR` is set. Animation is disabled for redirected output or `TERM=dumb`. Use a terminal at least 80 columns wide.

## Automatic exports

After automated checks complete, the scanner writes both formats to `exports/` beneath the directory where you launched it:

```text
gmaps_scan_<UTC timestamp>_<unique suffix>.json
gmaps_scan_<UTC timestamp>_<unique suffix>.csv
```

Both contain these fields, in order:

```text
id, api_type, status, cost_table, poc
```

- JSON contains an array of result records.
- CSV uses UTF-8 with a BOM for Excel compatibility.
- `--vulnerable` filters both the table and exports. Without it, all checked results are included.
- Empty filtered results produce an empty JSON array and a CSV header row.
- Interrupted scans or request exceptions do not produce completed-scan exports.
- Exports can contain the supplied API key. Redact them before sharing.

## API coverage

| Group | Checks |
| --- | --- |
| Maps and imagery | Staticmap, Streetview |
| Directions and routes | Directions, Distance Matrix, computeRoutes, computeRouteMatrix |
| Location | Geocode, Geolocation, Elevation, Timezone |
| Roads | Nearest Roads, Snap to Roads, Speed Limits |
| Places | Find Place From Text, Autocomplete, Place Details, Nearby Search, Text Search, Places Photo |
| Additional services | Address Validation, Air Quality, Aerial View, FCM |
| Gemini | Files and Cached Contents |
| Manual check | Maps JavaScript API |

Gemini checks run only when the FCM check does not return HTTP 200.

The JavaScript check creates `jsapi_test.html` for browser inspection and deletes it after you confirm completion. Use `--no-jsapi` to skip it.

## Docker

From the cloned repository:

```sh
docker build -t gmapsapiscanner .
docker run --rm -v "./exports:/opt/html/exports" gmapsapiscanner "YOUR_KEY" --vulnerable --no-jsapi
```

The image already supplies `--api-key`; pass the key directly after the image name. The mounted folder retains exported results.

## Evidence

## Important Note

Use the scanner only with keys and systems you are authorized to test. Requests may consume quota or incur charges.

The `vulnerable` label reflects the scanner’s response checks. Validate findings against the key’s intended permissions and the program’s reporting scope.

## Credits and license

Original project by **Ozgur Alp**, with API discovery and cost-information contributions from **Yatin**.

- [Unauthorized Google Maps API Key Usage Cases](https://medium.com/bugbountywriteup/unauthorized-google-maps-api-key-usage-cases-and-why-you-need-to-care-1ccb28bf21e)
- [Google Maps API Bugs Found Over the Years](https://medium.com/bugbountywriteup/google-maps-api-not-the-key-bugs-that-i-found-over-the-years-781840fc82aa)

Released under the MIT License. See [LICENSE](LICENSE).

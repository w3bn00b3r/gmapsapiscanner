import requests
import warnings
import json
import sys
import os
import builtins
import re
import shlex
import subprocess
import shutil
import textwrap
import threading
import csv
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from colorama import just_fix_windows_console

# Timeout for HTTP requests (seconds)
REQUEST_TIMEOUT = 15

# Common request kwargs (disable SSL verify for compatibility; use in tests only)
_REQUEST_KWARGS = {"verify": False, "timeout": REQUEST_TIMEOUT}


def _configure_proxy(proxy_url):
    """Add proxy settings to the shared request kwargs."""
    if proxy_url:
        _REQUEST_KWARGS["proxies"] = {"http": proxy_url, "https": proxy_url}


def _error_message(response, keys=("error_message", "errorMessage")):
    """Safely extract error message from JSON response to avoid KeyError."""
    try:
        data = response.json()
        # Some APIs (e.g. Routes computeRouteMatrix) return an array of items; first element may contain error
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            data = data[0]
        for key in keys:
            if key in data:
                val = data[key]
                if isinstance(val, dict) and "message" in val:
                    return val["message"]
                if isinstance(val, str):
                    return val
        if "error" in data and isinstance(data["error"], dict):
            return data["error"].get("message", str(data["error"]))
    except (json.JSONDecodeError, TypeError):
        pass
    if response.content:
        try:
            return response.content[:500].decode("utf-8", errors="replace").strip()
        except Exception:
            return str(response.content[:200])
    return "Unknown error (status %s)" % getattr(response, "status_code", "?")


def _color_enabled():
    """Keep redirected output plain; support legacy and modern consoles."""
    if "NO_COLOR" in os.environ or not sys.stdout.isatty():
        return False
    # Colorama translates ANSI to Win32 calls in legacy console hosts.
    return os.name == "nt" or os.environ.get("TERM") != "dumb"


def _console_print(*values, **kwargs):
    just_fix_windows_console()
    text = " ".join(str(value) for value in values)
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    if _color_enabled():
        color = "36"
        if "not vulnerable" in text or text.startswith("No vulnerable"):
            color = "32"
        elif "vulnerable" in text or text.startswith("- "):
            color = "1;31"
        elif text.startswith("Reason:"):
            color = "33"
        text = "\033[" + color + "m" + text + "\033[0m"
    builtins.print(text, **kwargs)


def _curl_poc(url, body, headers):
    """Quote POST PoCs for POSIX shells or Windows PowerShell on Windows."""
    args = ["curl.exe" if os.name == "nt" else "curl", "-i", "-s", "-k", "-X", "POST"]
    for name, value in headers.items():
        args.extend(["-H", name + ": " + value])
    args.extend(["--data-binary", body, url])
    if os.name == "nt":
        # Quote the URL even without spaces: CMD treats & as a separator.
        command = subprocess.list2cmdline(args[:-1]) + ' "' + url + '"'
        return ("Command Prompt (cmd.exe):\n" + command +
                "\nWindows PowerShell 3.0+:\ncurl.exe --% " +
                subprocess.list2cmdline(args[1:-1]) + ' "' + url + '"')
    return shlex.join(args)



_API_COSTS = {'Staticmap API': '$2 per 1000 requests',
 'Streetview API': '$7 per 1000 requests',
 'Directions API': '$5 per 1000 requests\nDirections (Advanced): $10 per 1000 requests',
 'Geocode API': '$5 per 1000 requests',
 'Distance Matrix API': '$5 per 1000 elements\nDistance Matrix (Advanced): $10 per 1000 elements',
 'Find Place From Text API': '$17 per 1000 elements',
 'Autocomplete API': '$2.83 per 1000 requests\nAutocomplete Per Session: $17 per 1000 requests',
 'Elevation API': '$5 per 1000 requests',
 'Timezone API': '$5 per 1000 requests',
 'Nearest Roads API': '$10 per 1000 requests',
 'Geolocation API': '$5 per 1000 requests',
 'Route to Traveled API': '$10 per 1000 requests',
 'Speed Limit-Roads API': '$20 per 1000 requests',
 'Place Details API': '$17 per 1000 requests',
 'Nearby Search-Places API': '$32 per 1000 requests',
 'Text Search-Places API': '$32 per 1000 requests',
 'Places Photo API': '$7 per 1000 requests',
 'Address Validation API': '$5 per 1000 requests',
 'Air Quality API': 'Paid per request',
 'Aerial View API': 'Paid per request',
 'Routes API (computeRoutes)': 'Paid per request',
 'Routes API (computeRouteMatrix)': 'Paid per element',
 'FCM API': 'https://abss.me/posts/fcm-takeover/',
 'Gemini Files API': 'Data Leak Risk '
                     'https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules',
 'Gemini Cached Contents API': 'Data Leak Risk'}


class _ResultTable:
    """Collect complete findings for the console and automatic exports."""

    def __init__(self, vulnerable_only=False):
        self.vulnerable_only = vulnerable_only
        self.rows = []

    def add(self, api_type, status, poc=""):
        if not self.vulnerable_only or status == "vulnerable":
            self.rows.append([api_type, status, poc, _API_COSTS.get(api_type, "Not specified")])

    def reason(self, message):
        if self.rows and self.rows[-1][1] == "not vulnerable":
            self.rows[-1][2] = message

    def render(self):
        just_fix_windows_console()
        headers = ["#", "API-Type", "Status", "Cost Table", "POC"]
        rows = [[str(i), row[0], row[1], row[3], row[2]] for i, row in enumerate(self.rows, 1)]
        # Preserve spaces and every character in PoCs when wrapping.
        width = max(79, shutil.get_terminal_size((120, 24)).columns - 1)
        number_width = max(1, len(str(len(rows))))
        api_width = min(31, max(16, width // 5))
        cost_width = min(30, max(15, width // 5))
        widths = [number_width, api_width, 14]
        poc_width = max(10, width - sum(widths) - cost_width - 16)
        widths.extend([cost_width, poc_width])
        border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

        def emit(cells, status=None):
            padded = [cell.ljust(w) for cell, w in zip(cells, widths)]
            if _color_enabled():
                if status and cells[2]:
                    color = "1;31" if status == "vulnerable" else "32"
                    padded[2] = "\033[" + color + "m" + padded[2] + "\033[0m"
                elif cells == headers:
                    padded = ["\033[1;36m" + cell + "\033[0m" for cell in padded]
            builtins.print("| " + " | ".join(padded) + " |")

        builtins.print(border)
        emit(headers)
        builtins.print(border)
        for row in rows:
            wrapped = []
            for value, cell_width in zip(row, widths):
                # Prevent tabs/control characters from corrupting terminal layout.
                value = re.sub(r"[\x00-\x09\x0b-\x1f\x7f]", " ", value)
                parts = []
                for part in value.split("\n"):
                    parts.extend(textwrap.wrap(part, width=cell_width,
                        replace_whitespace=False, drop_whitespace=False,
                        break_long_words=True, break_on_hyphens=False) or [""])
                wrapped.append(parts)
            for index in range(max(map(len, wrapped))):
                emit([parts[index] if index < len(parts) else "" for parts in wrapped], row[2])
            builtins.print(border)

    def export(self):
        """Save the displayed findings with full, unwrapped values in both formats."""
        fields = ["id", "api_type", "status", "cost_table", "poc"]
        records = [dict(zip(fields, [i, row[0], row[1], row[3], row[2]])) for i, row in enumerate(self.rows, 1)]
        directory = Path.cwd() / "exports"
        created = []
        try:
            directory.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%fZ")
            stem = "gmaps_scan_" + stamp + "_" + uuid4().hex[:8]
            json_path = directory / (stem + ".json")
            csv_path = directory / (stem + ".csv")
            with json_path.open("x", encoding="utf-8") as handle:
                created.append(json_path)
                json.dump(records, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
            with csv_path.open("x", encoding="utf-8-sig", newline="") as handle:
                created.append(csv_path)
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(records)
        except OSError as exc:
            for path in created:
                try:
                    path.unlink()
                except OSError:
                    pass
            _console_print("Export failed: " + str(exc))
            return False
        _console_print("JSON saved: " + str(json_path))
        _console_print("CSV saved:  " + str(csv_path))
        return True


class _ScanAnimation:
    """ASCII-only animation using carriage returns, including legacy CMD."""

    def __init__(self, enabled=True):
        just_fix_windows_console()
        self.stream = sys.stdout
        self.enabled = enabled and self.stream.isatty() and os.environ.get("TERM") != "dumb"
        self.color = _color_enabled()
        self.event = threading.Event()
        self.thread = None

    @staticmethod
    def frame(index):
        word = "scanning"
        position = index % len(word)
        return word[:position] + word[position].upper() + word[position + 1:] + "..."

    def _write_frame(self, index):
        label = self.frame(index)
        if self.color:
            label = "\033[36m" + label + "\033[0m"
        self.stream.write("\r" + label)
        self.stream.flush()

    def _run(self):
        index = 1
        while not self.event.wait(0.12):
            try:
                self._write_frame(index)
            except (OSError, ValueError):
                return
            index += 1

    def __enter__(self):
        if self.enabled:
            self._write_frame(0)
            self.thread = threading.Thread(target=self._run, daemon=True, name="scan-animation")
            self.thread.start()
        return self

    def stop(self):
        if self.thread is not None:
            self.event.set()
            self.thread.join()
            self.thread = None
            self.stream.write("\r" + " " * 11 + "\r")
            self.stream.flush()

    def __exit__(self, *exc):
        self.stop()


def scan_gmaps(apikey, skip_jsapi=False, proxy=None, vulnerable_only=False,
               no_animation=False):
    with _ScanAnimation(enabled=not no_animation) as animation:
        return _scan_gmaps_checks(apikey, skip_jsapi, proxy, vulnerable_only,
                                  animation)


def _scan_gmaps_checks(apikey, skip_jsapi, proxy, vulnerable_only, animation):
	print = _console_print
	table = _ResultTable(vulnerable_only)
	negative = table.reason
	_configure_proxy(proxy)
	url = "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200:
		table.add('Staticmap API', "vulnerable", url)
	elif b"PNG" in response.content:
		table.add('Staticmap API', "not vulnerable")
		negative("Reason: Manually check the "+url+" to view the reason.")
	else:
		table.add('Staticmap API', "not vulnerable")
		negative("Reason: "+ str(response.content))

	url = "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200:
		table.add('Streetview API', "vulnerable", url)
	elif b"PNG" in response.content:
		table.add('Streetview API', "not vulnerable")
		negative("Reason: Manually check the "+url+" to view the reason.")
	else:
		table.add('Streetview API', "not vulnerable")
		negative("Reason: "+ str(response.content))

	url = "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key="+apikey
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		table.add('Directions API', "vulnerable", url)
	else:
		table.add('Directions API', "not vulnerable")
		negative("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		table.add('Geocode API', "vulnerable", url)
	else:
		table.add('Geocode API', "not vulnerable")
		negative("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		table.add('Distance Matrix API', "vulnerable", url)
	else:
		table.add('Distance Matrix API', "not vulnerable")
		negative("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key="+apikey
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		table.add('Find Place From Text API', "vulnerable", url)
	else:
		table.add('Find Place From Text API', "not vulnerable")
		negative("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		table.add('Autocomplete API', "vulnerable", url)
	else:
		table.add('Autocomplete API', "not vulnerable")
		negative("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		table.add('Elevation API', "vulnerable", url)
	else:
		table.add('Elevation API', "not vulnerable")
		negative("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("errorMessage") < 0:
		table.add('Timezone API', "vulnerable", url)
	else:
		table.add('Timezone API', "not vulnerable")
		negative("Reason: "+ _error_message(response, ("errorMessage", "error_message")))

	url = "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		table.add('Nearest Roads API', "vulnerable", url)
	else:
		table.add('Nearest Roads API', "not vulnerable")
		negative("Reason: "+ _error_message(response, ("error",)))

	url = "https://www.googleapis.com/geolocation/v1/geolocate?key="+apikey 
	postdata = {'considerIp': 'true'}
	response = requests.post(url, data=postdata, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		table.add('Geolocation API', "vulnerable", _curl_poc(url, json.dumps(postdata), {"Content-Type": "application/json"}))
	else:
		table.add('Geolocation API', "not vulnerable")
		negative("Reason: "+ _error_message(response, ("error",)))

	url = "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		table.add('Route to Traveled API', "vulnerable", url)
	else:
		table.add('Route to Traveled API', "not vulnerable")
		negative("Reason: "+ _error_message(response, ("error",)))

	url = "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error") < 0:
		table.add('Speed Limit-Roads API', "vulnerable", url)
	else:
		table.add('Speed Limit-Roads API', "not vulnerable")
		negative("Reason: "+ _error_message(response, ("error",)))

	url = "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		table.add('Place Details API', "vulnerable", url)
	else:
		table.add('Place Details API', "not vulnerable")
		negative("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		table.add('Nearby Search-Places API', "vulnerable", url)
	else:
		table.add('Nearby Search-Places API', "not vulnerable")
		negative("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key="+apikey 
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.text.find("error_message") < 0:
		table.add('Text Search-Places API', "vulnerable", url)
	else:
		table.add('Text Search-Places API', "not vulnerable")
		negative("Reason: "+ _error_message(response))

	url = "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key="+apikey 
	response = requests.get(url, **{**_REQUEST_KWARGS, "allow_redirects": False})
	if response.status_code == 302:
		table.add('Places Photo API', "vulnerable", url)
	else:
		table.add('Places Photo API', "not vulnerable")
		negative("Reason: Verbose responses are not enabled for this API, cannot determine the reason.")

	# Address Validation API (POST)
	url = "https://addressvalidation.googleapis.com/v1:validateAddress?key=" + apikey
	postdata = json.dumps({"address": {"regionCode": "US", "addressLines": ["1600 Amphitheatre Pkwy, Mountain View, CA"]}})
	response = requests.post(url, data=postdata, headers={"Content-Type": "application/json"}, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		table.add('Address Validation API', "vulnerable", _curl_poc(url, postdata, {"Content-Type": "application/json"}))
	else:
		table.add('Address Validation API', "not vulnerable")
		negative("Reason: " + _error_message(response, ("error",)))

	# Air Quality API (POST)
	url = "https://airquality.googleapis.com/v1/currentConditions:lookup?key=" + apikey
	postdata = json.dumps({"location": {"latitude": 37.419734, "longitude": -122.0827784}})
	response = requests.post(url, data=postdata, headers={"Content-Type": "application/json"}, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		table.add('Air Quality API', "vulnerable", _curl_poc(url, postdata, {"Content-Type": "application/json"}))
	else:
		table.add('Air Quality API', "not vulnerable")
		negative("Reason: " + _error_message(response, ("error",)))

	# Aerial View API (GET) - video metadata lookup
	url = "https://aerialview.googleapis.com/v1/videos:lookupVideoMetadata?key=" + apikey + "&address=600%20Montgomery%20St%2C%20San%20Francisco%2C%20CA%2094111"
	response = requests.get(url, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		table.add('Aerial View API', "vulnerable", url)
	else:
		table.add('Aerial View API', "not vulnerable")
		negative("Reason: " + _error_message(response, ("error",)))

	# Routes API - computeRoutes (POST, requires field mask)
	url = "https://routes.googleapis.com/directions/v2:computeRoutes?key=" + apikey
	headers = {"Content-Type": "application/json", "X-Goog-FieldMask": "routes.duration,routes.distanceMeters,routes.polyline.encodedPolyline"}
	body = {
		"origin": {"location": {"latLng": {"latitude": 37.419734, "longitude": -122.0827784}}},
		"destination": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}},
		"travelMode": "DRIVE",
	}
	response = requests.post(url, data=json.dumps(body), headers=headers, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0 and "routes" in response.text:
		table.add('Routes API (computeRoutes)', "vulnerable", _curl_poc(url, json.dumps(body), headers))
	else:
		table.add('Routes API (computeRoutes)', "not vulnerable")
		negative("Reason: " + _error_message(response, ("error",)))

	# Routes API - computeRouteMatrix (POST)
	url = "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key=" + apikey
	headers = {"Content-Type": "application/json", "X-Goog-FieldMask": "originIndex,destinationIndex,status,distanceMeters,duration"}
	body = {
		"origins": [{"waypoint": {"location": {"latLng": {"latitude": 37.419734, "longitude": -122.0827784}}}}],
		"destinations": [
			{"waypoint": {"location": {"latLng": {"latitude": 37.4220, "longitude": -122.0841}}}},
			{"waypoint": {"location": {"latLng": {"latitude": 37.4250, "longitude": -122.0860}}}},
		],
		"travelMode": "DRIVE",
	}
	response = requests.post(url, data=json.dumps(body), headers=headers, **_REQUEST_KWARGS)
	if response.status_code == 200 and response.text.find("error") < 0:
		table.add('Routes API (computeRouteMatrix)', "vulnerable", _curl_poc(url, json.dumps(body), headers))
	else:
		table.add('Routes API (computeRouteMatrix)', "not vulnerable")
		negative("Reason: " + _error_message(response, ("error",)))

	url = "https://fcm.googleapis.com/fcm/send" 
	postdata = "{'registration_ids':['ABC']}"
	response = requests.post(url, data=postdata, **_REQUEST_KWARGS, headers={'Content-Type':'application/json','Authorization':'key='+apikey})
	if response.status_code == 200:
		table.add('FCM API', "vulnerable", _curl_poc(url, json.dumps({"registration_ids": ["ABC"]}), {"Content-Type": "application/json", "Authorization": "key=" + apikey}))
	else:
		table.add('FCM API', "not vulnerable")
		reason_found = False
		for line in response.iter_lines():
			if line and b"TITLE" in line:
				try:
					msg = line.decode("utf-8", errors="replace").split("TITLE")[1].split("<")[0].replace(">", "").strip()
					if msg:
						negative("Reason: " + msg)
						reason_found = True
						break
				except (IndexError, AttributeError):
					pass
		if not reason_found:
			negative("Reason: " + _error_message(response, ("error",)) if response.content else ("HTTP %s" % response.status_code))
	
		# Gemini Files API (GET)
		url = "https://generativelanguage.googleapis.com/v1beta/files?key=" + apikey
		response = requests.get(url, **_REQUEST_KWARGS)

		if response.status_code == 200:
		    table.add('Gemini Files API', "vulnerable", url)
		else:
		    table.add('Gemini Files API', "not vulnerable")
		    negative("Reason: " + _error_message(response, ("error",)))

		# Gemini Cached Contents API (GET)
		url = "https://generativelanguage.googleapis.com/v1beta/cachedContents?key=" + apikey
		response = requests.get(url, **_REQUEST_KWARGS)

		if response.status_code == 200:
		    table.add('Gemini Cached Contents API', "vulnerable", url)
		else:
		    table.add('Gemini Cached Contents API', "not vulnerable")
		    negative("Reason: " + _error_message(response, ("error",)))
		    
	animation.stop()
	table.render()
	if not any(row[1] == "vulnerable" for row in table.rows):
		print("No vulnerable APIs detected by the automated checks.")
	export_ok = table.export()
	print("Reference for up-to-date pricing:")
	print("https://cloud.google.com/maps-platform/pricing")
	print("https://developers.google.com/maps/billing/gmp-billing")
	if skip_jsapi:
		print("Skipping JavaScript API test (--no-jsapi).")
	else:
		jsapi = input("Do you want to conduct tests for Javascript API? (Will need manual confirmation + file creation) (Y/N)")
		if jsapi == "Y" or jsapi == "y":
			f = open("jsapi_test.html","w+", encoding="utf-8")
			f.write('<!DOCTYPE html><html><head><script src="https://maps.googleapis.com/maps/api/js?key='+apikey+'&callback=initMap&libraries=&v=weekly" defer></script><style type="text/css">#map{height:100%;}html,body{height:100%;margin:0;padding:0;}</style><script>let map;function initMap(){map=new google.maps.Map(document.getElementById("map"),{center:{lat:-34.397,lng:150.644},zoom:8,});}</script></head><body><div id="map"></div></body></html>')
			print("jsapi_test.html file is created for manual confirmation. Open it at your browser and observe whether the map is successfully loaded or not.")
			f.close()
			print("If you see 'Sorry! Something went wrong.' error on the page, it means that API key is not allowed to be used at JavaScript API.")
			result = input("Press enter again for deletion of jsapi_test.html file automatically after manual confirmation is conducted.")
			os.remove("jsapi_test.html")
	print("Operation is over. Thanks for using G-Maps API Scanner!")
	return export_ok

def main() -> None:
	print = _console_print
	warnings.filterwarnings("ignore")
	args = sys.argv[1:]
	no_animation = "--no-animation" in args
	args = [a for a in args if a != "--no-animation"]
	vulnerable_only = "--vulnerable" in args
	args = [a for a in args if a != "--vulnerable"]
	skip_jsapi = "--no-jsapi" in args
	if skip_jsapi:
		args = [a for a in args if a != "--no-jsapi"]

	# Extract --proxy / -p value
	proxy = None
	for flag in ("--proxy", "-p"):
		if flag in args:
			idx = args.index(flag)
			if idx + 1 < len(args):
				proxy = args[idx + 1]
				args = args[:idx] + args[idx + 2:]
			else:
				print("Missing proxy URL after %s, aborting." % flag)
				_print_usage()
				return
			break

	if proxy:
		print("Using proxy: " + proxy)

	if len(args) > 0:
		if args[0] == "--api-key" or args[0] == "-a":
			if len(args) == 2 and not args[1].startswith("-"):
				scan_gmaps(args[1], skip_jsapi=skip_jsapi, proxy=proxy, vulnerable_only=vulnerable_only, no_animation=no_animation)
			else:
				print("Missing API key or invalid arguments, aborting.")
				_print_usage()
		elif args[0] == "--help" or args[0] == "-h":
			_print_usage()
		else:
			print("Invalid arguments, aborting.")
			_print_usage()
	else:
		apikey = input("Please enter the Google Maps API key you wanted to test: ")
		scan_gmaps(apikey, skip_jsapi=skip_jsapi, proxy=proxy, vulnerable_only=vulnerable_only, no_animation=no_animation)


def _print_usage() -> None:
	print = _console_print
	print("Usage: python maps_api_scanner.py [--api-key KEY] [--proxy URL] [--no-jsapi] [--vulnerable] [--no-animation]")
	print("       gmapsapiscanner [--api-key KEY] [--proxy URL] [--no-jsapi] [--vulnerable] [--no-animation]")
	print("  --api-key, -a   API key to test (otherwise prompted for input)")
	print("  --proxy, -p     HTTP/HTTPS/SOCKS proxy URL (e.g. http://127.0.0.1:8080)")
	print("  --no-jsapi      Skip the interactive JavaScript API test (useful for CI/automation)")
	print("  --vulnerable    Show only vulnerable results and PoCs (all checks still run)")
	print("  --no-animation  Disable the dancing Scanning... indicator")
	print("  --help, -h      Show this message")

if __name__ == "__main__":
    main()


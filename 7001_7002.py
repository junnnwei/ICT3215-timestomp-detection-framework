import pandas as pd
import json
import re

def build_on_off_structure(input_csv, output_json):
    df = pd.read_csv(input_csv)

    df['timestamp'] = df['date'].astype(str).str.strip() + "T" + df['time'].astype(str).str.strip()

    on_codes = {'7001'}
    off_codes = {'7002'}

    events = {"logon": [], "logoff": []}

    # Correct XML EventID extraction
    provider_regex = re.compile(r'<Provider\s+[^>]*Name="Microsoft-Windows-Winlogon"[^>]*/?>', re.IGNORECASE)
    _event_id_re = re.compile(r'<EventID(?:\s+[^>]*)?>(\d+)</EventID>', re.IGNORECASE)

    class EventIDWithProvider:
        def __init__(self, provider_re, eventid_re):
            self.provider_re = provider_re
            self.eventid_re = eventid_re
        def search(self, text):
            if not text:
                return None
            # only return an EventID match if the required Provider is present
            if not self.provider_re.search(text):
                return None
            return self.eventid_re.search(text)

    event_id_regex = EventIDWithProvider(provider_regex, _event_id_re)

    for _, row in df.iterrows():
        extra = str(row.get("extra", ""))

        # Extract event ID from XML
        match = event_id_regex.search(extra)
        if not match:
            continue

        code = match.group(1)
        timestamp = row['timestamp']

        # Collect ON/OFF events
        if code in on_codes:
            events["logon"].append({"timestamp": timestamp, "code": code})

        elif code in off_codes:
            events["logoff"].append({"timestamp": timestamp, "code": code})

    # Save to JSON
    with open(output_json, "w") as f:
        json.dump(events, f, indent=4)


# Example usage:
build_on_off_structure('input.csv', 'output.json')

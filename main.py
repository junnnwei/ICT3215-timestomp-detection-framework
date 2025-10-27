import pandas as pd
import os, json, re, yaml, networkx, datetime

# Global Declaration
linkedEntities = {}

# Function: Check Plaso timeline CSV file presence
def checkSourceFiles():
    # Ensure 'source/' directory exists
    if not os.path.exists('source'):
        os.makedirs('source')
        print("Created 'source/' directory.")

    # Load and display the CSV file
    csv_path = os.path.join('source', 'timeline.csv')

    if os.path.isfile(csv_path):
        return True

    else:
        print("'timeline.csv' not found inside 'source/'. Please place it there before running this script.")
        return False

# Function: Process the timestamps & include a validity flag
def processTimestamps(df):
    combined = df["date"].astype(str).str.strip() + " " + df["time"].astype(str).str.strip()

    # Try to parse; invalid ones become NaT
    df["datetime"] = pd.to_datetime(
        combined,
        format="%m/%d/%Y %H:%M:%S",
        errors="coerce"
    )

    # Flag invalid or placeholder (1601) timestamps
    df["is_valid_time"] = True

    df.loc[
        (df["datetime"].isna()) | (df["datetime"].dt.year == 1601),
        "is_valid_time"
    ] = False

    return df

# Function: Normalize file path for keying
def normalizeKey(path):
    """Normalize a file path to a consistent format for keying"""
    # Lowercase
    path = path.strip().lower()

    # Remove prefixes:
    path = re.sub(r'^(ntfs:|path:)\s*', '', path)
    path = re.sub(r'^[a-z]:[\\/]', '', path)       # remove drive letter prefix (e.g. C:)
    path = re.sub(r'^\\+', '', path)          # remove leading backslashes

    # Replace backslashes with forward slashes for consistency
    path = path.replace('\\', '/')

    # Remove trailing details for PCA Logs & UserAssist REGKEY
    path = re.sub(r'\s+was run$', '', path)            # PCA
    path = re.sub(r'\s+count:\s*\d+$', '', path)       # UserAssist
    
    return path.strip()

# Function: Obtain prefetch naming without hash and .pf extension
def stripPrefetchName(path):
    basename = os.path.basename(path.strip())

    # Remove the trailing -HASH.pf part (the hash is always 8 hex characters)
    match = re.match(r"([a-z0-9_\-\.]+\.exe)-[a-f0-9]{8}\.pf$", basename, re.I)
    if match:
        return match.group(1).lower()
    
    # Fallback: if no hash suffix, just strip .pf
    if basename.lower().endswith(".pf"):
        return basename.lower().replace(".pf", "")

    return basename.lower()

def stripUSNJournalName(path):
    basename = os.path.basename(path.strip().lower())
    match = re.match(r"([a-z0-9_\-\.]+\.pf)", basename, re.I)
    if match:
        return match.group(1).lower()

def stripUSNJournalINode(short):
    # Extract inode from short description
    match = re.search(r'\b(\d+)-\d+\b', short)
    return match.group(1) if match else None

# Function: special handling for linking UsnJournal entries
def buildUSNJournalLookups(linkedEntities):
    inode_to_key = {}
    pf_to_key = {}

    for key, value in linkedEntities.items():
        for subheader, entries in value.items():
            if subheader == "PE_COFF":
                for entry in entries:
                    inode = entry.get("inode")
                    if inode:
                        inode_to_key[inode] = key

            elif subheader == "PREFETCH":
                for entry in entries:
                    prefetch_filename = entry.get("prefetch_filename")
                    if prefetch_filename:
                        pf_to_key.setdefault(prefetch_filename, set()).add(key)
    
    return inode_to_key, pf_to_key

# Function: link UsnJournal entry to existing linkedEntities
def linkUSNEntry(row, inode_to_key, pf_to_key):
    src = row.get("source", "").lower().strip()
    srctype = row.get("sourcetype", "").lower().strip()

    if not (src == "file" and srctype == "ntfs usn change"):
        return
    
    short = row.get("short", "").lower().strip()
    original_filename = str(row.get("filename", "")).lower().strip()
    macb = row.get("MACB", "").lower().strip()
    datetime = row.get("datetime", "")
    isValidTime = row.get("is_valid_time")

    # Convert timestamp for readability
    datetime_str = datetime.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(datetime) else None

    logType = "$USN_JOURNAL"

    # inode matching for PE/COFF files
    inode = stripUSNJournalINode(short)
    # print(f"Linking USN Entry: inode={inode}, short={short}")

    if inode and inode in inode_to_key:
        key = inode_to_key[inode]
        # print(f"Matched USN Entry to key: {key} using inode: {inode})")
        linkedEntities[key].setdefault(logType, []).append({
            "datetime": datetime_str,
            "original_filename": original_filename,
            "isValidTime": isValidTime,
            "short_description": short,
            "macb": macb
        })
        return

    # Prefetch filename matching
    pf_name = stripUSNJournalName(short)
    if pf_name in pf_to_key:
        for key in pf_to_key[pf_name]:
            # print(f"Matched USN Entry to key: {key} using prefetch filename: {pf_name})")
            linkedEntities[key].setdefault(logType, []).append({    
                "datetime": datetime_str,
                "original_filename": original_filename,
                "isValidTime": isValidTime,
                "short_description": short,
                "macb": macb,
                "prefetch_name": pf_name
            })

# Function: Form linked entities (excl. $UsnJournal)
def deriveLinkedEntities(row):
    """Derivation of linked entities ID based on analysis of sources"""
    src = row.get("source", "").lower().strip()
    srctype = row.get("sourcetype", "").lower().strip()
    short = row.get("short", "").lower().strip()
    inode = row.get("inode", "")
    original_filename = str(row.get("filename", "")).lower().strip()
    filename = normalizeKey(original_filename)
    macb = row.get("MACB", "").lower().strip()
    datetime = row.get("datetime", "")
    isValidTime = row.get("is_valid_time")

    # Convert timestamp for readability
    datetime_str = datetime.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(datetime) else None

    # Anchor using $MFT entries: prefetch & MFT share the same src & srctype; can be differentiated using 'short'
    if src == "file" and srctype == "file stat" and r"\windows\prefetch" not in short:
        # print(f"Found $MFT for {filename}")
        logType = "$MFT"
        
        if filename not in linkedEntities:
            linkedEntities[filename] = {}
        
        if logType not in linkedEntities[filename]:
            linkedEntities[filename][logType] = []
            
        linkedEntities[filename][logType].append({
            "datetime": datetime_str,
            "original_filename": original_filename,
            "isValidTime": isValidTime,
            "short_description": short,
            "macb": macb
        })
    
    # Amcache: for Amcache, the short description contains the path which matches the data structure key
    if src == "amcache" and srctype == "amcache registry entry":
        logType = "AMCACHE"

        normalizedShort = normalizeKey(short)

        # Account for situations whereby $MFT doesn't exist, but Amcache does (not common, but possible)
        if normalizedShort not in linkedEntities:
            linkedEntities[normalizedShort] = {}

        if logType not in linkedEntities[normalizedShort]:
            linkedEntities[normalizedShort][logType] = []
        
        linkedEntities[normalizedShort][logType].append({
            "datetime": datetime_str,
            "original_filename": original_filename,
            "isValidTime": isValidTime,
            "short_description": short,
            "macb": macb
        })
    
    # AppCompatCache: similar to Amcache
    if src == "reg" and srctype == "appcompatcache registry key":
        logType = "APPCOMPATCACHE"

        normalizedShort = normalizeKey(short)

        # Account for situations whereby $MFT doesn't exist, but AppCompatCache does
        if normalizedShort not in linkedEntities:
            linkedEntities[normalizedShort] = {}

        if logType not in linkedEntities[normalizedShort]:
            linkedEntities[normalizedShort][logType] = []
        
        linkedEntities[normalizedShort][logType].append({
            "datetime": datetime_str,
            "original_filename": original_filename,
            "isValidTime": isValidTime,
            "short_description": short,
            "macb": macb
        })
    
    # Program Compatibility Log
    if src == "log" and srctype == "program compatibility assistant (pca) log":
        logType = "PCA_LOG"

        normalizedShort = normalizeKey(short)

        if normalizedShort not in linkedEntities:
            linkedEntities[normalizedShort] = {}

        if logType not in linkedEntities[normalizedShort]:
            linkedEntities[normalizedShort][logType] = []
        
        linkedEntities[normalizedShort][logType].append({
            "datetime": datetime_str,
            "original_filename": original_filename,
            "isValidTime": isValidTime,
            "short_description": short,
            "macb": macb
        })
    
    # UserAssist REGKEY
    if src == "reg" and srctype == "userassist registry key":
        logType = "USERASSIST_REGKEY"

        normalizedShort = normalizeKey(short)

        if normalizedShort not in linkedEntities:
            linkedEntities[normalizedShort] = {}

        if logType not in linkedEntities[normalizedShort]:
            linkedEntities[normalizedShort][logType] = []
        
        linkedEntities[normalizedShort][logType].append({
            "datetime": datetime_str,
            "original_filename": original_filename,
            "isValidTime": isValidTime,
            "short_description": short,
            "macb": macb
        })
    
    # PE/COFF
    if src == "pe" and srctype == "pe/coff file":
        logType = "PE_COFF"

        if filename not in linkedEntities:
            linkedEntities[filename] = {}
        
        if logType not in linkedEntities[filename]:
            linkedEntities[filename][logType] = []
        
        linkedEntities[filename][logType].append({
            "datetime": datetime_str,
            "original_filename": original_filename,
            "isValidTime": isValidTime,
            "inode": inode,
            "macb": macb
        })
    
    # Prefetch
    if src == "file" and srctype == "file stat" and r"\windows\prefetch" in short:
        logType = "PREFETCH"

        prefetchBinary = stripPrefetchName(short)
        pf_name = os.path.basename(short)

        # Find matching entity key
        # Try direct filename match with normalized linkedEntities keys
        matches = [key for key in linkedEntities.keys() if key.endswith("/" + prefetchBinary)]

        if matches:
            for key in matches:
                linkedEntities[key].setdefault(logType, []).append({
                    "datetime": datetime_str,
                    "isValidTime": isValidTime,
                    "exe_name": prefetchBinary,
                    "original_filename": original_filename,
                    "short": short,
                    "prefetch_filename": pf_name
                })

    # $UsnJournal (deprecated due to extreme big-O complexity; replaced with buildUSNJournalLookups + linkUSNEntry):
    # if src == "file" and srctype == "ntfs usn change":
    #     logType = "$USN_JOURNAL"

    # #     # Match using filename and inode criterion (our program targets .exe and .dlls, so we will use PE/COFF inode for linking
    #     for key, value in linkedEntities.items():
    #         for subheader, entries in value.items():
    #             print(subheader, entries)
    #             # This is for the file itself; not prefetch
    #             if subheader == "PE_COFF":
    #                 for entry in entries:
    #                     if entry.get("inode") == stripUSNJournalINode(short) and stripUSNJournalName(short) in entry.get("original_filename"):
    #                         # Found a match
    #                         if logType not in linkedEntities[key]:
    #                             linkedEntities[key][logType] = []
                            
    #                         linkedEntities[key][logType].append({
    #                             "datetime": datetime_str,
    #                             "original_filename": original_filename,
    #                             "isValidTime": isValidTime,
    #                             "short_description": short,
    #                             "macb": macb
    #                         })
    #                         break  # No need to check further PE_COFF entries for this key
                
    #             # # Link prefetch-related entries in $USNJournal
    #             if subheader == "PREFETCH":
    #                 for entry in entries:
    #                     # Example: CREATION_FUTURE.EXE-70488A55.pf 753134-3 USN_REASON_SECURITY_CHANGE (short entry) vs "prefetch_filename": "creation_future.exe-70488a55.pf" (in linkedEntities)
    #                     if entry.get("prefetch_filename") == os.path.basename(short):
    #                         # Found a match
    #                         if logType not in linkedEntities[key]:
    #                             linkedEntities[key][logType] = []
                            
    #                         linkedEntities[key][logType].append({
    #                             "datetime": datetime_str,
    #                             "original_filename": original_filename,
    #                             "isValidTime": isValidTime,
    #                             "short_description": short,
    #                             "macb": macb,
    #                             "pf_name": os.path.basename(short)
    #                         })
    #                         break  # No need to check further PREFETCH entries for this key

# Function: Parse the linked entities from JSON
def parseLinkedEntities():
    with open(os.path.join('source', 'linked_entities.json'), 'r', encoding='utf-8') as f:
        data = json.load(f)

    return data

# Function: Parse power on/off events from JSON
def parsePowerEvents():
    path = os.path.join('source', 'power_events.json')
    if not os.path.exists(path):
        print("[-] power_events.json not found.")
        return []

    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    on_events = data.get("on", [])
    off_events = data.get("off", [])

    # Deduplicate based on timestamp
    on_events = list({e["timestamp"]: e for e in on_events if "timestamp" in e}.values())
    off_events = list({e["timestamp"]: e for e in off_events if "timestamp" in e}.values())

    # Sort by timestamp
    on_events = sorted(on_events, key=lambda x: x["timestamp"])
    off_events = sorted(off_events, key=lambda x: x["timestamp"])

    # Parse timestamp format like "09/14/2025T06:32:25"
    def parse_ts(ts):
        ts = ts.strip().replace("T", " ")
        try:
            return pd.to_datetime(ts, format="%m/%d/%Y %H:%M:%S", errors="coerce")
        except Exception:
            return pd.to_datetime(ts, errors="coerce")

    # Convert and store parsed timestamps
    on_times = [(parse_ts(e["timestamp"]), e.get("code", "")) for e in on_events]
    off_times = [(parse_ts(e["timestamp"]), e.get("code", "")) for e in off_events]
    # print(f"On Time: {on_times}")
    # print(f"Off Time: {off_times}")

    # Pair each shutdown → next startup
    boot_sessions = []
    for off_time, off_code in off_times:
        # Find the first startup event *after* this shutdown
        next_on = next(((t, c) for t, c in on_times if t > off_time), None)
        if next_on:
            on_time, on_code = next_on
            boot_sessions.append({
                "next_boot_start": on_time,
                "previous_boot_end": off_time,
                "on_code": on_code,
                "off_code": off_code
            })

    return boot_sessions


# Function: Parse YAML Rules
def parseYAMLRules(yaml_path):
    if not os.path.exists(yaml_path):
        print(f"YAML rules file not found: {yaml_path}")
        return None

    with open(yaml_path, 'r', encoding='utf-8') as f:
        rules = yaml.safe_load(f)

    return rules.get("rules", [])

def get_datetime(linkedEntities, srcLog, macb_filter=None):
    # MACB attributes are file system timestamps that record a file's Modified, Accessed, Changed (metadata), and Birth (creation) times.
    entries = linkedEntities.get(srcLog, [])
    valid_times = []

    for e in entries:
        dt = e.get("datetime")
        
        # Skip if MACB filter is specified and doesn't match
        if macb_filter:
            # Apply MACB filter
            macb = e.get("macb", "")
            if macb_filter not in macb:
                continue
        
        # If datetime = null or isValidTime = false, skip
        if not dt or not e.get("isValidTime"):
            # print("dateTime is NULL or isValidTime is false. Skipping.")
            continue
        
        # print(dt)
        valid_times.append(pd.to_datetime(dt))
    
    return valid_times

# Function: Evaluate Conditions
def evaluate_condition(condition, linkedEntities, boot_sessions):
    condition = condition.strip()
    macb_filter = None

    # Extract MACB filter if necessary
    macb_match = re.search(r"macb=['\"]([macb\.\-]+)['\"]", condition)
    if macb_match:
        macb_filter = macb_match.group(1)
    
    # --- RULE HANDLER SECTION ---
    # Major Rule 1 Handler:
    # Example:
    # - datetime($MFT) not between (BOOT_SESSIONS)
    # - datetime($MFT, macb='m.c.') not between (BOOT_SESSIONS) [or any other MACB variants, m.c. tested here since it matches an event in our linkedEntities]
    if "not between (BOOT_SESSIONS)" in condition:
        src_match = re.search(r"datetime\(([^),]+)", condition)
        if not src_match:
            return {"violated": False}

        srcLog = src_match.group(1).strip()
        timestamps = get_datetime(linkedEntities, srcLog, macb_filter)
        # print(f"srcLog: {srcLog}, timestamps: {timestamps}, macb_filter: {macb_filter}")

        if not timestamps or not boot_sessions:
            return {"violated": False}
        
        # Iterate through every matched timestamp & check against boot sessions
        for ts in timestamps:
            # outOfSession = any((pd.to_datetime(session["previous_boot_end"]) <= ts <= pd.to_datetime(session["next_boot_start"])) for session in boot_sessions)
            offendingSession = next((session for session in boot_sessions if pd.to_datetime(session["previous_boot_end"]) <= ts <= pd.to_datetime(session["next_boot_start"])), None)
            
            # Found a timestamp outside boot sessions
            # if outOfSession:
            if offendingSession:
                # Find closest power-off context for context reporting
                next_boot_start = pd.to_datetime(offendingSession.get("next_boot_start"))
                previous_boot_end = pd.to_datetime(offendingSession.get("previous_boot_end"))
                on_code = offendingSession.get("on_code", "")
                off_code = offendingSession.get("off_code", "")
            
                return {
                    "violated": True,
                    "violating_event": {
                        "src": srcLog,
                        "timestamp": str(ts),
                        "macb_filter": macb_filter or "N/A",
                    },
                    "context": {
                        "boot_session": {
                            "next_boot_start": str(next_boot_start),
                            "previous_boot_end": str(previous_boot_end),
                            "on_code": on_code,
                            "off_code": off_code,
                        },
                        "description": (
                            f"File timestamp {ts} falls outside the last known boot session (Previous Power Off @ {previous_boot_end} (Event Code: {off_code}); Next Power On @ {next_boot_start} (Event Code: {on_code})."
                        )
                    }
                }
            
        # All timestamps are within boot sessions
        return {"violated": False}

    # --- Default return for unhandled rule types ---
    return {"violated": False}
    
# Function: Rule Evaluation
# To be implemented: ensure rules are structurally correct and all fields can be obtained
def evaluateRules(yamlRules, linkedEntities, boot_sessions):
    ruleViolations = []
    for key, evidence in linkedEntities.items():
        # For testing purposes, only evaluate a specific key
        if key == "users/timel/desktop/cases/creation_future.exe":
            # print(key, evidence)
            for rule in yamlRules:
                logic = rule.get("logic", {})
                triggeredInfo = []

                if "any_of" in logic:
                    for condition in logic["any_of"]:
                        result = evaluate_condition(condition["condition"], evidence, boot_sessions)
                        if result.get("violated"):
                            triggeredInfo.append(result)

                elif "all_of" in logic:
                    allResults = []
                    for condition in logic["all_of"]:
                        result = evaluate_condition(condition["condition"], evidence, boot_sessions)
                        allResults.append(result)

                    # Check if all conditions are violated
                    if all(res.get("violated") for res in allResults):
                        triggeredInfo.extend(allResults)

            if triggeredInfo:
                ruleViolations.append({
                    "entity": key,
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name"),
                    "severity": rule.get("severity"),
                    "explanation": rule.get("explanation"),
                    "violations": triggeredInfo
                })

    print(json.dumps(ruleViolations, indent=4))
    return ruleViolations


if __name__ == "__main__":
    while True:
        print("==================================================")
        print("ICT3215 TIMESTOMP DETECTION FRAMEWORK".center(50))
        print("==================================================")
        electedOption = input("1. Process timeline.csv and derive linked entities\n2. YAML Rule Builder (GUI)\n3. Parse YAML Rules & Validate\n4. Exit\nEnter choice (1-4): ").strip()
        
        if electedOption == '1':
            if checkSourceFiles():
                print("[PARSING] Parsing timeline.")
                df = pd.read_csv('source/timeline.csv', low_memory=False)
                # print(df.columns)
                # print(df.head())

                # Processing: removal of browser noise
                print("[CLEANING] Removing browser history entries.")
                df = df[~df["source"].isin(["WEBHIST"])]

                # Process timestamps & mark the invalid ones
                print("[PROCESSING] Proessing timestamps.")
                df = processTimestamps(df)

                # Build LinkedEntities without USNJournal first
                print("[LINKING] Building linked entities.")
                for _, row in df.iterrows():
                    deriveLinkedEntities(row)

                # Build O(1) lookups for USN linking
                inode_to_key, pf_to_key = buildUSNJournalLookups(linkedEntities)
                # print(inode_to_key)
                # print(pf_to_key)

                # Link USN rows using lookups
                usn_mask = (df["source"].str.lower() == "file") & (df["sourcetype"].str.lower() == "ntfs usn change")
                usn_df = df[usn_mask]
                # print(usn_df)

                for _, row in usn_df.iterrows():
                    linkUSNEntry(row, inode_to_key, pf_to_key)

                # sumOfUSNEntries = 0
                # for key, value in linkedEntities.items():
                #     if "$USN_JOURNAL" in value:
                #         print(value)
                #         sumOfUSNEntries += 1
                
                # print(f"[DEBUG] Entities with $USN_JOURNAL: {sumOfUSNEntries}")

                # For the sake of checking: output to file
                print("[WRITING] Writing linked entities to JSON file.")
                output_path = os.path.join('source', 'linked_entities.json')

                # Convert to JSON and write to file
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(linkedEntities, f, indent=4, ensure_ascii=False)
                
                print(f"[+] Linked entities saved to: {output_path}")

                print(f"[+] Deriving Windows events.")
                
                # WuHao write your function/code here for deriving Windows events

                print(f"[+] Windows events derived successfully.")
        
        elif electedOption == '2':
            print("Option 2 selected. (Rule builder functionality to be implemented)")

        elif electedOption == '3':
            # Read linkedEntities
            print("[+] Parsing linked entities from JSON.")
            linkedEntities = parseLinkedEntities()
            print("[+] Linked entities parsed successfully.")

            # Parse power on/off events
            print("[+] Parsing power on/off events.")
            boot_sessions = parsePowerEvents()
            # print(boot_sessions)

            # Parse YAML rules for detection
            print("[+] Parsing YAML Rules.")
            yamlRules = parseYAMLRules('timestomp_rules.yaml')

            if yamlRules is None:
                print("[-] Failed to parse YAML rules. Please check the file.")
                continue

            print(f"[YAML PARSER] {len(yamlRules)} rules parsed successfully.")

            # Validate linked entities against rules
            evaluateRules(yamlRules, linkedEntities, boot_sessions)
        
        elif electedOption == '4':
            print("Exiting program.")
            break

        else:
            print("Invalid option. Please select 1, 2, or 3.")
import pandas as pd
import os, json, re, yaml, networkx, datetime, subprocess, glob

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

    if not os.path.isfile(csv_path):
        print("'timeline.csv' not found inside 'source/'. Please place it there before running this script.")
        return False

    # Check for Amcache.hve file presence
    amcache_path = os.path.join('source', 'Amcache.hve')

    if not os.path.isfile(amcache_path):
        print("'Amcache.hve' not found inside 'source/'. Please place it there before running this script.")
        return False
    
    return True

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

# Function: Execute Amcache Parser & Perform Linking
def executeAmcacheParser(linkedEntities):
    amcache_path = os.path.join('source', 'Amcache.hve')
    output_dir = os.path.join('source', 'amcache_output')

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Tool path
    amcacheParser = os.path.join('support-tools', 'AmcacheParser.exe')
    cmd = [amcacheParser, '-f', amcache_path, '--csv', output_dir]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    # Verify
    if "Results saved to: source\\amcache_output" in result.stdout:
        pattern = os.path.join(output_dir, '*_Amcache_UnassociatedFileEntries.csv')
        csv_files = glob.glob(pattern)
        csv_path = csv_files[0]

        amcache_df = pd.read_csv(csv_path, low_memory=False)
        
        # From experimenting, there'll sometimes be a row with a blank fullpath
        amcache_df = amcache_df.dropna(subset=["FullPath"])  # drop NaN
        amcache_df = amcache_df[amcache_df["FullPath"].astype(str).str.strip() != ""]
        
        count = 0
        for _, row in amcache_df.iterrows():
            file_path = str(row.get("FullPath", "")).strip().lower()
            timestamp = str(row.get("FileKeyLastWriteTimestamp", "")).strip().lower()

            normalized_path = normalizeKey(file_path)
            dt = pd.to_datetime(timestamp, errors="coerce")
            dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            logType = "AMCACHE"

            linkedEntities.setdefault(normalized_path, {})
            linkedEntities[normalized_path].setdefault(logType, []).append({
                "datetime": dt_str,
                "original_filename": str(row.get("Name", "")),
                "isValidTime": True,
            })

            count += 1
        
        print(f"[+] Linked {count} Amcache entries into linkedEntities (timestamps normalized).")

        for file in os.listdir(output_dir):
            full_path = os.path.join(output_dir, file)
            try:
                os.remove(full_path)
            except:
                pass
        
        print("[CLEANING] Removed Amcache Parser files post-entity linkage.")

    else:
        print("[WARNING] Amcache Parser failed. Continuing without Amcache records.")



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
    # Update 2/11/25 1131 hrs: skipping Amcache handling as per new design decision

    # if src == "amcache" and srctype == "amcache registry entry":
    #     logType = "AMCACHE"

    #     type = row.get("type", "").lower().strip()

    #     if type == "link time":
    #         return # skip link time entries
        
    #     normalizedShort = normalizeKey(short)

    #     # Account for situations whereby $MFT doesn't exist, but Amcache does (not common, but possible)
    #     if normalizedShort not in linkedEntities:
    #         linkedEntities[normalizedShort] = {}

    #     if logType not in linkedEntities[normalizedShort]:
    #         linkedEntities[normalizedShort][logType] = []
        
    #     linkedEntities[normalizedShort][logType].append({
    #         "datetime": datetime_str,
    #         "original_filename": original_filename,
    #         "isValidTime": isValidTime,
    #         "short_description": short,
    #         "macb": macb,
    #         "type": type
    #     })
    
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
    
    # Sort chronologically
    valid_times.sort()

    return valid_times

# Function: Extract MACB Attributes defined in the rule YAML file from either left, right, or both, only applicable to conditions without "BOOT_SESSIONS"
# BOOT_SESSIONS conditions will be handled separately, and within rule builder tool, it shouldn't be created to have any operators
def extract_macb_filters(condition: str):
    # Split once on a comparison operator (keeps operator too)
    parts = re.split(r'\s*(<=|>=|==|!=|<|>)\s*', condition, maxsplit=1)
    if len(parts) < 3:
        return None, None  # malformed

    left_expr, op, right_expr = parts

    # Regex to extract macb='...' or macb="..."
    pattern = r"macb=['\"]([MACBmacb\.\-]+)['\"]"

    left_match = re.search(pattern, left_expr)
    right_match = re.search(pattern, right_expr)

    left_macb_filter = left_match.group(1) if left_match else None
    right_macb_filter = right_match.group(1) if right_match else None

    return left_macb_filter, right_macb_filter

# Function: Evaluate Conditions
def evalCondition(condition, linkedEntities, boot_sessions, allowed_latency):
    condition = condition.strip()
    macb_filter = None
    DRIFT_TOLERANCE = pd.Timedelta(seconds=int(allowed_latency))
    
    # --- RULE HANDLER SECTION ---
    # Major Rule 1 Handler:
    # Example:
    # - datetime($MFT) not between (BOOT_SESSIONS)
    # - datetime($MFT, macb='m.c.') not between (BOOT_SESSIONS) [or any other MACB variants, m.c. tested here since it matches an event in our linkedEntities]
    if "not between (BOOT_SESSIONS)" in condition:
        # Extract MACB filter if necessary
        macb_match = re.search(r"macb=['\"]([macb\.\-]+)['\"]", condition)
        if macb_match:
            macb_filter = macb_match.group(1)
                
        src_match = re.search(r"datetime\(([^),]+)", condition)
        srcLog = src_match.group(1).strip()

        # Theoretically unreachable, just error handling
        timestamps = get_datetime(linkedEntities, srcLog, macb_filter)
        # print(f"srcLog: {srcLog}, timestamps: {timestamps}, macb_filter: {macb_filter}")

        if not timestamps:
            return {
                "violated": False,
                "inconclusive": True,
                "reason": "timestamps_not_found",
                "context": {
                    "description": f"Source: {srcLog} with MACB='{macb_filter}' not found."
                }
            }
        
        if not boot_sessions:
            return {
                "violated": False,
                "inconclusive": True,
                "reason": "boot_sessions_not_found",
                "context": {
                    "description": f"Boot sessions missing."
                }
            }
        
        # Iterate through every matched timestamp & check against boot sessions
        for ts in timestamps:
            # outOfSession = any((pd.to_datetime(session["previous_boot_end"]) <= ts <= pd.to_datetime(session["next_boot_start"])) for session in boot_sessions)
            offendingSession = next((session for session in boot_sessions if (pd.to_datetime(session["previous_boot_end"]) + DRIFT_TOLERANCE) <= ts <= (pd.to_datetime(session["next_boot_start"]) - DRIFT_TOLERANCE)), None)
            
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
                    "boot_sessions_involvement": True,
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

    # Major Rule 2 Handler:
    else:
        src_match = re.findall(r"datetime\(([^),]+)", condition)

        # Technically unreachable, just error handling
        if len(src_match) < 2:
            return {"violated": False}

        left_entity = src_match[0].strip()
        right_entity = src_match[1].strip()

        # Extract MACB filter
        macb_match = re.findall(r"macb=['\"]([macb\.\-]+)['\"]", condition)
        left_macb_filter, right_macb_filter = extract_macb_filters(condition)

        left_timestamps = get_datetime(linkedEntities, left_entity, left_macb_filter)
        # print(f"Left: {left_timestamps}")
        right_timestamps = get_datetime(linkedEntities, right_entity, right_macb_filter)
        # print(f"Right: {right_timestamps}")

        if not left_timestamps:
            return {
                "violated": False,
                "inconclusive": True,
                "reason": "timestamps_not_found",
                "context": {
                    "description": f"Source: {left_entity} with MACB='{left_macb_filter}' not found."
                }
            }
        
        if not right_timestamps:
            return {
                "violated": False,
                "inconclusive": True,
                "reason": "timestamps_not_found",
                "context": {
                    "description": f"Source: {right_entity} with MACB='{right_macb_filter}' not found."
                }
            }

        # Extract comparison operator
        op_match = re.search(r"datetime\([^)]*\)\s*([<>!=]+)\s*datetime\([^)]*\)", condition)
        op = op_match.group(1).strip() if op_match else None
        
        # Technically unreachable, just error handling
        if not op:
            return {"violated": False}
        
        # Comparison Portion
        cmp_map = {
            "<": lambda l, r: l < r,
            "<=": lambda l, r: l <= r,
            ">": lambda l, r: l > r,
            ">=": lambda l, r: l >= r,
            "==": lambda l, r: l == r,
            "!=": lambda l, r: l != r,
        }
    
        # print(f"Operator: {op}")

        # Theoretically unreachable, just error handling
        if not left_timestamps or not right_timestamps:
            return {"violated": False}
        
        # print(f"{left_timestamps[0]} {op} {right_timestamps[0]} → {cmp_map[op](left_timestamps[0], right_timestamps[0])}")
        # print(f"Left Timestamps: {left_timestamps}, Right Timestamps: {right_timestamps}")

        if op in ["<", "<="]:
            rt_adj = right_timestamps[0] - DRIFT_TOLERANCE
        elif op in [">", ">="]:
            rt_adj = right_timestamps[0] + DRIFT_TOLERANCE
        else:
            rt_adj = right_timestamps[0]

        if cmp_map[op](left_timestamps[0], rt_adj):
            return {
                "violated": True,
                "boot_sessions_involvement": False,
                "violating_event": {
                    "left_src": left_entity,
                    "left_timestamp": str(left_timestamps[0]),
                    "left_macb_filter": left_macb_filter or "N/A",
                    "right_src": right_entity,
                    "right_timestamp": str(right_timestamps[0]),
                    "right_macb_filter": right_macb_filter or "N/A",
                    "operator": op
                },
                "context": {
                    "description": (
                        f"Condition violated: {left_entity} (MACB: {left_macb_filter}) timestamp {left_timestamps[0]} {op} {right_entity} (MACB: {right_macb_filter}) timestamp {right_timestamps[0]}"
                    )
                }
            }

    # --- Default return for unhandled rule types ---
    return {"violated": False}
    
# Function: Rule Evaluation
# To be implemented: ensure rules are structurally correct and all fields can be obtained
def evaluateRules(yamlRules, linkedEntities, boot_sessions):
    print("[RULE EVALUATION] Evaluating linked entities against YAML rules.")
    ruleViolations = []
    for key, evidence in linkedEntities.items():
        # For testing purposes, only evaluate a specific key
        # if key == "users/timel/desktop/cases/creation_future.exe":
        # if key == "users/timel/downloads/ntimestomp_v1.2_x64.exe":
        # print(key, evidence)
        for rule in yamlRules:
            logic = rule.get("logic", {})
            allowed_latency = rule.get("latency-buffer-seconds")
            triggeredInfo = []
            inconclusiveInfo = []

            if "any_of" in logic:
                for condition in logic["any_of"]:
                    result = evalCondition(condition["condition"], evidence, boot_sessions, allowed_latency)
                    if result.get("violated"):
                        triggeredInfo.append(result)

                    # To be done: handle inconclusive separately
                    elif result.get("inconclusive") and result not in inconclusiveInfo:
                        inconclusiveInfo.append(result)

            elif "all_of" in logic:
                allResults = []
                for condition in logic["all_of"]:
                    result = evalCondition(condition["condition"], evidence, boot_sessions, allowed_latency)
                    allResults.append(result)

                # Check if all conditions are violated
                if all(res.get("violated") for res in allResults):
                    triggeredInfo.extend(allResults)
                
                # Collect inconclusive results
                for res in allResults:
                    if res.get("inconclusive") and res not in inconclusiveInfo:
                        inconclusiveInfo.append(res)

            if triggeredInfo or inconclusiveInfo:
                ruleViolations.append({
                    "entity": key,
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name"),
                    "severity": rule.get("severity"),
                    "explanation": rule.get("explanation"),
                    "violations": triggeredInfo if triggeredInfo else None,
                    "inconclusive": inconclusiveInfo if inconclusiveInfo else None
                })

    # print(json.dumps(ruleViolations, indent=4))

    filterForViolations(ruleViolations)

    return ruleViolations

def filterForViolations(ruleViolations):
    violations_only = [rv for rv in ruleViolations if rv.get("violations")]

    print(json.dumps(violations_only, indent=4))
    return violations_only

if __name__ == "__main__":
    while True:
        print("==================================================")
        print("ICT3215 TIMESTOMP DETECTION FRAMEWORK".center(50))
        print("==================================================")
        electedOption = input("1. Link Relevant Entities\n2. YAML Rule Builder (GUI)\n3. Parse YAML Rules & Validate\n4. Exit\nEnter choice (1-4): ").strip()
        
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

                # New: Amcache Linker as per new design decision
                executeAmcacheParser(linkedEntities)

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
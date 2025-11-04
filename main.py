import pandas as pd
import os, json, re, yaml, networkx, datetime, subprocess, glob, fnmatch

# Global Declaration
linkedEntities = {}

# Function: Check Plaso timeline CSV file presence
def checkSourceFiles():
    # Ensure 'source/' directory exists
    if not os.path.exists('source'):
        os.makedirs('source', exist_ok=True)
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

    prefetchPath = os.path.join('source/prefetch')
    os.makedirs(prefetchPath, exist_ok=True)

    if not any(os.scandir(prefetchPath)):
        print(f"No prefetch files detected. Please extract them using FTK Imager/Encase and place it in {prefetchPath}.")
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
    path = re.sub(r'^volume\{[0-9a-f\-]+\}[\\/]*', '', path) # remove volume{...} prefix from WinPrefetchView

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
                    prefetch_filename = entry.get("prefetch_filename").lower()
                    if prefetch_filename:
                        pf_to_key.setdefault(prefetch_filename, set()).add(key)
    
    return inode_to_key, pf_to_key

# Function: link UsnJournal entry to existing linkedEntities
def linkUSNEntry(row, inode_to_key, pf_to_key):
    src = row.get("source", "").lower().strip()
    srctype = row.get("sourcetype", "").lower().strip()

    if not (src == "file" and srctype == "ntfs usn change"):
        return
    
    short = row.get("short", "").lower()
    original_filename = str(row.get("filename", "")).lower().strip()
    macb = row.get("MACB", "").lower().strip()
    datetime = row.get("datetime", "")
    isValidTime = row.get("is_valid_time")
    description = row.get("desc", "")

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
            "long_description": description,
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
                "long_description": description,
                "macb": macb,
                "prefetch_filename": pf_name
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

# Function: Execution of WinPrefetchView to accurately link prefetch files
def executeWinPrefetchView(linkedEntities):
    logType = "PREFETCH"
    print("[+] WinPrefetchView Processing")
    prefetch_path = os.path.join('source', 'prefetch')
    prefetchCSVSource = os.path.join('source/prefetch.csv')

    # Tool path
    winPrefetchView = os.path.join('support-tools', 'WinPrefetchView.exe')

    # WinPrefetchView.exe /folder "C:\Users\User\Downloads\DF Project\Prefetch" /scomma prefetch.csv
    cmd = [winPrefetchView, '/folder', prefetch_path, '/scomma', prefetchCSVSource]
    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
    
    except Exception as e:
        print("[-] Failed to run WinPrefetchView.exe, did you run the program as administrator?")
        return

    # Parse the prefetch.csv
    if os.path.isfile(prefetchCSVSource):
        df = pd.read_csv(prefetchCSVSource)

        # Drop missing fields for processpath
        df = df[df["Process Path"].notna() & (df["Process Path"] != "") & (df["Process Path"] != "nan")]
        df = df[df["Last Run Time"].notna() & (df["Last Run Time"] != "") & (df["Last Run Time"] != "nan")]
        df = df[df["Created Time"].notna() & (df["Created Time"] != "") & (df["Created Time"] != "nan")]

        # print(df)
        # print(df["Process Path"].apply(normalizeKey))

        df["Process Path Normalized"] = df["Process Path"].apply(normalizeKey)

        for _, row in df.iterrows():
            processPath = row["Process Path Normalized"]
            timestamp = row.get("Last Run Time")
            splittedTimestamps = timestamp.split(",")

            if processPath not in linkedEntities:
                linkedEntities[processPath] = {}
            
            if logType not in linkedEntities[processPath]:
                linkedEntities[processPath][logType] = []

            # Add entries iteratively
            for ts in splittedTimestamps:
                ts = ts.strip()
                cleanTS = datetime.datetime.strptime(ts, "%d-%b-%y %I:%M:%S %p").strftime("%Y-%m-%d %H:%M:%S")
                linkedEntities[processPath][logType].append({
                    "datetime": cleanTS,
                    "creation_time": datetime.datetime.strptime(row.get("Created Time").strip(), "%d-%b-%y %I:%M:%S %p").strftime("%Y-%m-%d %H:%M:%S"),
                    "modified_time": datetime.datetime.strptime(row.get("Modified Time"), "%d-%b-%y %I:%M:%S %p").strftime("%Y-%m-%d %H:%M:%S"),
                    "prefetch_filename": row.get("Filename"),
                    "executable_filename": row.get("Process EXE"),
                    "isValidTime": True,
                    "original_process_path": row.get("Process Path")
                })
    
        os.remove(prefetchCSVSource)

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
    # Update 3/11/25: This is now deprecated, we'll use WinPrefetchView instead to obtain the most accurate information
    # if src == "file" and srctype == "file stat" and r"\windows\prefetch" in short:
    #     logType = "PREFETCH"

    #     prefetchBinary = stripPrefetchName(short)
    #     pf_name = os.path.basename(short)

    #     # Find matching entity key
    #     # Try direct filename match with normalized linkedEntities keys
    #     matches = [key for key in linkedEntities.keys() if key.endswith("/" + prefetchBinary)]

    #     if matches:
    #         for key in matches:
    #             linkedEntities[key].setdefault(logType, []).append({
    #                 "datetime": datetime_str,
    #                 "isValidTime": isValidTime,
    #                 "exe_name": prefetchBinary,
    #                 "original_filename": original_filename,
    #                 "short": short,
    #                 "prefetch_filename": pf_name
    #             })

# Function: Parse the linked entities from JSON
def parseLinkedEntities():
    with open(os.path.join('source', 'linked_entities.json'), 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    for key, value in data.items():
        for src_name, entries in value.items():
            for e in entries:
                dt = e.get("datetime")
                if isinstance(dt, str):
                    try:
                        e["datetime"] = pd.Timestamp(dt)
                    except:
                        e["datetime"] = None

    return data

# Function: Parse Winlogon (7002)/Winlogoff (7002) events from JSON
def parseAuthenticationEvents():
    """ Returns authentication pairs; this project assumes that there'll no clean startup and shutdowns, thereby forming pairs. Future work: power on/off events"""
    path = os.path.join('source', 'winlogauthentication_events.json')
    if not os.path.exists(path):
        print("[-] winlogauthentication_events.json not found.")
        return []

    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    on_events = data.get("logon", [])
    off_events = data.get("logoff", [])

    # Deduplicate based on timestamp
    on_events = sorted([e for e in data.get("logon", []) if "timestamp" in e],
                       key=lambda x: x["timestamp"])
    
    off_events = sorted([e for e in data.get("logoff", []) if "timestamp" in e],
                        key=lambda x: x["timestamp"])

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
    auth_sessions = []
    off_idx = 0

    for on_time, on_code in on_times:
        # paired = False
        while off_idx < len(off_times):
            off_time, off_code = off_times[off_idx]

            if off_time > on_time:
                auth_sessions.append({
                    "logon_start": on_time,
                    "logoff_end": off_time,
                    "on_code": on_code,
                    "off_code": off_code,
                    # "status": "closed"
                })

                off_idx += 1
                # paired = True
                break
            
            off_idx += 1
        
        # if not paired:
        #     # no later logoff → open session
        #     auth_sessions.append({
        #         "logon_start": on_time,
        #         "logoff_end": None,
        #         "on_code": on_code,
        #         "off_code": None,
        #         "status": "open"
        #     })
            
    return auth_sessions

# Function: Parse YAML Rules
def parseYAMLRules(yaml_path):
    if not os.path.exists(yaml_path):
        print(f"YAML rules file not found: {yaml_path}")
        return None

    with open(yaml_path, 'r', encoding='utf-8') as f:
        rules = yaml.safe_load(f)

    return rules.get("rules", [])

def get_datetime(linkedEntities, srcLog):
    # MACB attributes are file system timestamps that record a file's Modified, Accessed, Changed (metadata), and Birth (creation) times.
    if '.' not in srcLog:
        raise ValueError(f"[FORMAT ERROR] Condition missing attribute: '{srcLog}'")
    
    src_name, attr = srcLog.split(".", 1)
    src_name = src_name.strip()
    attr = attr.strip()
    valid_times = []

    entries = linkedEntities.get(src_name, [])
    if not entries:
        return []
    
    # Special handling for $MFT
    if src_name == "$MFT":
        MACB_MAP = {
            "none": "....",
            "creation": "...b",
            "metachange": "..c.",
            "metachange_creation": "..cb",
            "accessed": ".a..",
            "accessed_creation": ".a.b",
            "accessed_metachange": ".ac.",
            "accessed_metachange_creation": ".acb",
            "modified": "m...",
            "modified_creation": "m..b",
            "modified_metachange": "m.c.",
            "modified_metachange_creation": "m.cb",
            "modified_accessed": "ma..",
            "modified_accessed_creation": "ma.b",
            "modified_accessed_metachange": "mac.",
            "modified_accessed_metachange_creation": "macb"
        }
    
        # .birth maps to ...b
        expectedMACB = MACB_MAP.get(attr)

        for e in entries:
            if not e.get("isValidTime", True):
                continue
            
            macb = e.get("macb")

            # Check if $MFT has the particular MACB variant that is being looked for
            if expectedMACB != macb:
                continue

            dt = e.get("datetime")
            if not dt:
                continue
        
            valid_times.append(pd.to_datetime(dt))
    
    # Prefetch Handling
    elif src_name == "PREFETCH":
        if attr == "firstrun":
            # Use creation time
            for e in entries:
                if not e.get("isValidTime", True):
                    continue
                
                dt = e.get("creation_time")
                if not dt:
                    continue

                valid_times.append(pd.to_datetime(dt))
        
        elif attr == "lastrun":
            # Use the final execution timestamp
            all_runs = []
            for e in entries:
                if not e.get("isValidTime", True):
                    continue

                dt = e.get("datetime")
                if not dt:
                    continue
            
                all_runs.append(pd.to_datetime(dt))
            
            if all_runs:
                valid_times.append(max(all_runs))

        # Iterate through everything and return; these are max of past 8 runs
        else:
            for e in entries:
                if not e.get("isValidTime", True):
                    continue

                dt = e.get(attr)
                
                if not dt:
                    continue

                valid_times.append(pd.to_datetime(dt))

    # USNJournal Handling
    elif src_name == "$USN_JOURNAL":
        # VALID_USN_REASONS = {
        #     "USN_REASON_DATA_OVERWRITE",
        #     "USN_REASON_DATA_EXTEND",
        #     "USN_REASON_DATA_TRUNCATION",
        #     "USN_REASON_BASIC_INFO_CHANGE",
        #     "USN_REASON_FILE_CREATE",
        #     "USN_REASON_FILE_DELETE",
        #     "USN_REASON_CLOSE",
        #     "USN_REASON_RENAME_OLD_NAME",
        #     "USN_REASON_RENAME_NEW_NAME",
        #     "USN_REASON_SECURITY_CHANGE",
        #     "USN_REASON_STREAM_CHANGE",
        #     "USN_REASON_OBJECT_ID_CHANGE",
        #     "USN_REASON_HARD_LINK_CHANGE",
        #     "USN_REASON_REPARSE_POINT_CHANGE"
        # }

        selectedReasons = [reason.strip().upper() for reason in attr.split("|")]

        if not selectedReasons:
            return []
        
        for e in entries:
            if not e.get("isValidTime", True):
                continue

            desc = e.get("long_description").strip()
            match = re.search(r"Update reason:\s*(.+)", desc)

            if not match:
                continue
            
            reasons_raw = match.group(1)
            found_reasons = re.findall(r"USN_REASON_[A-Z_]+", reasons_raw.upper())

            if set(found_reasons) == set(selectedReasons):
                dt = e.get("datetime")

                if not dt:
                    continue

                valid_times.append(pd.to_datetime(dt))

    # Other log types
    else:
        for e in entries:
            if not e.get("isValidTime", True):
                continue
            
            # Use direct attribute field
            dt = e.get(attr)

            if not dt:
                continue

            valid_times.append(pd.to_datetime(dt))

    # Sort chronologically
    valid_times.sort()

    return valid_times

# Function: Evaluate Conditions
def evalCondition(condition, linkedEntities, auth_sessions):
    condition = condition.strip()
    
    # --- RULE HANDLER SECTION ---
    # Major Rule 1 Handler:
    # Example:
    # - datetime($MFT) not between (AUTHENTICATION_SESSIONS)
    # - datetime($MFT, macb='m.c.') not between (AUTHENTICATION_SESSIONS) [or any other MACB variants, m.c. tested here since it matches an event in our linkedEntities]
    if "not between (AUTH_SESSIONS)" in condition:   
        src_match = re.search(r"datetime\(([^),]+)", condition)
        srcLog = src_match.group(1).strip()

        # Theoretically unreachable, just error handling
        timestamps = get_datetime(linkedEntities, srcLog)

        if not timestamps:
            return {
                "violated": False,
                "inconclusive": True,
                "reason": "timestamps_not_found",
                "context": {
                    "description": f"Source: {srcLog} not found."
                }
            }
        
        if not auth_sessions:
            return {
                "violated": False,
                "inconclusive": True,
                "reason": "auth_sessions_not_found",
                "context": {
                    "description": f"Auth sessions missing."
                }
            }
        
        # Iterate through every matched timestamp & check against auth sessions
        for ts in timestamps:
            offendingSession = next(
                (
                    {
                        "after_logoff": prev["logoff_end"],
                        "before_logon": nxt["logon_start"],
                        "off_code": prev.get("off_code"),
                        "on_code": nxt.get("on_code")
                    }
                    for prev, nxt in zip(auth_sessions, auth_sessions[1:])
                    if prev["logoff_end"] and nxt["logon_start"] and prev["logoff_end"] <= ts <= nxt["logon_start"]
                ),
                None
            )

            # If it's after the last logoff (and there's no new logon)
            if not offendingSession and auth_sessions:
                last_session = auth_sessions[-1]
                if last_session["logoff_end"] and ts > last_session["logoff_end"]:
                    offendingSession = {
                        "after_logoff": last_session["logoff_end"],
                        "before_logon": None,
                        "off_code": last_session.get("off_code"),
                        "on_code": None,
                        "note": "post_final_logoff"
                    }

            # Found a timestamp outside auth sessions
            # if outOfSession:
            if offendingSession:
                # Find closest power-off context for context reporting
                after_logoff = pd.to_datetime(offendingSession.get("after_logoff"))
                before_logon = pd.to_datetime(offendingSession.get("before_logon"))
                on_code = offendingSession.get("on_code", "")
                off_code = offendingSession.get("off_code", "")
            
                return {
                    "violated": True,
                    "auth_sessions_involvement": True,
                    "violating_event": {
                        "src": srcLog,
                        "timestamp": str(ts),
                        "operator": "not between"
                    },
                    "context": {
                        "auth_session": {
                            "previous_auth_end": str(after_logoff),
                            "next_auth_start": str(before_logon),
                            "on_code": on_code,
                            "off_code": off_code,
                        },
                        "description": (
                            f"File timestamp {ts} falls outside the last known authentication session (Previous Logoff @ {after_logoff} (Event Code: {off_code}); Next Logon @ {before_logon} (Event Code: {on_code})."
                        )
                    }
                }
        
        # All timestamps are within auth sessions
        return {"violated": False}

    # Major Rule 2 Handler:
    else:
        src_match = re.findall(r"datetime\(([^),]+)", condition)

        # Technically unreachable, just error handling
        if len(src_match) < 2:
            return {"violated": False}

        left_entity = src_match[0].strip()
        right_entity = src_match[1].strip()

        left_timestamps = get_datetime(linkedEntities, left_entity)
        # print(f"Left: {left_timestamps}")
        right_timestamps = get_datetime(linkedEntities, right_entity)
        # print(f"Right: {right_timestamps}")

        if not left_timestamps:
            return {
                "violated": False,
                "inconclusive": True,
                "reason": "timestamps_not_found",
                "context": {
                    "description": f"Source: {left_entity} not found."
                }
            }
        
        if not right_timestamps:
            return {
                "violated": False,
                "inconclusive": True,
                "reason": "timestamps_not_found",
                "context": {
                    "description": f"Source: {right_entity} not found."
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
        
        # print(f"Left Timestamps: {left_timestamps}, Right Timestamps: {right_timestamps}")
        for left_time in left_timestamps:
            for right_time in right_timestamps:
                if cmp_map[op](left_time, right_time):
                    return {
                        "violated": True,
                        "auth_sessions_involvement": False,
                        "violating_event": {
                            "left_src": left_entity,
                            "left_timestamp": str(left_time),
                            "right_src": right_entity,
                            "right_timestamp": str(right_time),
                            "operator": op
                        },
                        "context": {
                            "description": (
                                f"Condition violated: {left_entity} timestamp {left_time} {op} {right_entity} timestamp {right_time}"
                            )
                        }
                    }

    # --- Default return for unhandled rule types ---
    return {"violated": False}

# Function: Target matching
def matchTarget(key, target):
    if not isinstance(key, str) or not isinstance(target, str):
        return False
    
    # Match key against rule target; supporting exact match, substring match, wildcard and regex
    key = key.lower().strip()
    target = target.lower().strip()

    # Regex signature
    if target.startswith("r/"):
        pattern = target[2:]
        return re.fullmatch(pattern, key) is not None

    # Wildcard
    elif "*" in target:
        return fnmatch.fnmatch(key, target)

    # Substring
    elif target in key:
        return True
    
    else:
        return key == target

# Function: Filter evidence within specified timeframe
def filterEntitiesByRange(linkedEntities, timeframe=None):
    if not timeframe or not isinstance(timeframe, str) or timeframe.strip() == "":
        return linkedEntities

    cmp = {
        "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
    }

    parts = [p.strip() for p in timeframe.split("and") if p.strip()]
    conditions = []

    for part in parts:
        m = re.match(r"(>=|<=|>|<|==|!=)\s*([\d\-:\sT]+)", part.strip())
        if not m:
            continue

        op, val = m.groups()
        ts = pd.to_datetime(val.strip(), errors="coerce")

        # Include full day for <= or <
        if ts.time() == datetime.time(0, 0):
            if op in ("<", "<="):
                ts = ts + pd.Timedelta(days=1) - pd.Timedelta(milliseconds=1)
        
        conditions.append((op, ts))

    if not conditions:
        print(f"[WARNING] No valid timeframe parsed from: {timeframe}")
        return {}

    filtered = {}

    for key, sources in linkedEntities.items():
        for src_name, entries in sources.items():
            valid_entries = []
            for e in entries:
                dt = e.get("datetime")
                if not dt:
                    continue

                dt = pd.to_datetime(dt, errors="coerce")
                if pd.isna(dt):
                    continue

                if all(cmp[op](dt, ts) for op, ts in conditions):
                    valid_entries.append(e)

            if valid_entries:
                filtered.setdefault(key, {})[src_name] = valid_entries
    
    return filtered


# Function: Rule Evaluation
# To be implemented: ensure rules are structurally correct and all fields can be obtained
def evaluateRules(yamlRules, linkedEntities, auth_sessions):
    print("[RULE EVALUATION] Evaluating linked entities against YAML rules.")
    possibleViolations = []

    # Retrieve rule information
    for rule in yamlRules:
        # Default to all of the keys, but used for error handling. Preferably use "*"
        targets = rule.get("targets", list(linkedEntities.keys()))
        logic = rule.get("logic", {})

        for target in targets:
            for key, evidence in linkedEntities.items():
                # For testing purposes, only evaluate a specific key
                # if key == "users/timel/desktop/cases/creation_future.exe":
                if matchTarget(key, target):
                    triggeredInfo = []
                    inconclusiveInfo = []

                    if "any_of" in logic:
                        for condition in logic["any_of"]:
                            result = evalCondition(condition["condition"], evidence, auth_sessions)
                            if result.get("violated"):
                                triggeredInfo.append(result)

                            # To be done: handle inconclusive separately
                            elif result.get("inconclusive") and result not in inconclusiveInfo:
                                inconclusiveInfo.append(result)

                    elif "all_of" in logic:
                        allResults = []
                        for condition in logic["all_of"]:
                            result = evalCondition(condition["condition"], evidence, auth_sessions)
                            allResults.append(result)

                        # Check if all conditions are violated
                        if all(res.get("violated") for res in allResults):
                            triggeredInfo.extend(allResults)
                        
                        # Collect inconclusive results
                        for res in allResults:
                            if res.get("inconclusive") and res not in inconclusiveInfo:
                                inconclusiveInfo.append(res)

                    if triggeredInfo or inconclusiveInfo:
                        possibleViolations.append({
                            "entity": key,
                            "rule_id": rule.get("id"),
                            "rule_name": rule.get("name"),
                            "severity": rule.get("severity"),
                            "explanation": rule.get("explanation"),
                            "violations": triggeredInfo if triggeredInfo else None,
                            "inconclusive": inconclusiveInfo if inconclusiveInfo else None
                        })

    # print(json.dumps(possibleViolations, indent=4))
    confirmedViolations = filterForViolations(possibleViolations)

    if confirmedViolations:
        print(confirmedViolations)

    inconclusiveViolations = isInconclusive(possibleViolations)

    if inconclusiveViolations:
        print("Inconclusive:")
        print(inconclusiveViolations)
    
    if not confirmedViolations and not inconclusiveViolations:
        print("[NO VIOLATIONS] All results are not in violation and did not return any inconclusive verdict.")

    return possibleViolations

def filterForViolations(possibleViolations):
    violations_only = [pv for pv in possibleViolations if pv.get("violations")]

    return violations_only

def isInconclusive(possibleViolations):
    inconclusive_only = [pv for pv in possibleViolations if not pv.get("violations") and pv.get("inconclusive")]

    return inconclusive_only

if __name__ == "__main__":
    while True:
        print("==================================================")
        print("ICT3215 TIMESTOMP DETECTION FRAMEWORK".center(50))
        print("==================================================")
        electedOption = input("1. Link Relevant Entities\n2. YAML Rule Builder (GUI)\n3. Parse YAML Rules & Validate\n4. Exit\nEnter choice (1-4): ").strip()
        
        if electedOption == '1':
            if checkSourceFiles():
                # executeWinPrefetchView(linkedEntities)
                # test = input("ASDsadas: ")
                print("[PARSING] Parsing timeline.")
                df = pd.read_csv('source/timeline.csv', low_memory=False)
                # print(df.columns)
                # print(df.head())

                # Processing: removal of browser noise
                print("[CLEANING] Removing browser history entries.")
                df = df[~df["source"].isin(["WEBHIST"])]

                # Process timestamps & mark the invalid ones
                print("[PROCESSING] Processing timestamps.")
                df = processTimestamps(df)

                # Build LinkedEntities without USNJournal first
                print("[LINKING] Building linked entities.")
                for _, row in df.iterrows():
                    deriveLinkedEntities(row)

                # New: Amcache Linker as per new design decision
                executeAmcacheParser(linkedEntities)

                # New: Prefetch Linker as per new design decision
                executeWinPrefetchView(linkedEntities)

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

                # Remove PE/COFF due to inaccuracy of timestamp & lack of relevance to timestomp detection
                for file, logTypes in linkedEntities.items():
                    if "PE_COFF" in logTypes:
                        del linkedEntities[file]["PE_COFF"]

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
            linkedEntitiesUnfiltered = parseLinkedEntities()
            print("[+] Linked entities parsed successfully.")

            # Parse YAML rules for detection
            print("[+] Parsing YAML Rules.")
            yamlRules = parseYAMLRules('timestomp_rules.yaml')

            if yamlRules is None:
                print("[-] Failed to parse YAML rules. Please check the file.")
                continue
            
            print(f"[YAML PARSER] {len(yamlRules)} rules parsed successfully.")

            # Retrieve specified timeframe
            for rule in yamlRules:
                timeframe = rule.get("timeframe", None)

            linkedEntities = filterEntitiesByRange(linkedEntitiesUnfiltered, timeframe)
            
            # Parse power on/off events
            print("[+] Parsing power on/off events.")
            auth_sessions = parseAuthenticationEvents()
            # print(auth_sessions)

            # Validate linked entities against rules
            evaluateRules(yamlRules, linkedEntities, auth_sessions)
        
        elif electedOption == '4':
            print("Exiting program.")
            break

        else:
            print("Invalid option. Please select 1, 2, or 3.")

import pandas as pd
import os, json, re, yaml

# Global Declaration
linkedEntities = {}

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

# Special handling for linking UsnJournal entries
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

if __name__ == "__main__":
    while True:
        print("==================================================")
        print("ICT3215 TIMESTOMP DETECTION FRAMEWORK".center(50))
        print("==================================================")
        electedOption = input("1. Process timeline.csv and derive linked entities\n2. Parse YAML Rules & Validate\n3. Exit\nEnter choice (1-3): ").strip()
        
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
                print("[LINKING] Building lniked entities.")
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
        
        elif electedOption == '2':
            print("YAML Rules & Validation feature is under development.")
        
        elif electedOption == '3':
            print("Exiting program.")
            break

        else:
            print("Invalid option. Please select 1, 2, or 3.")
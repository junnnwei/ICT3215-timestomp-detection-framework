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

    # $UsnJournal

if __name__ == "__main__":
    if checkSourceFiles():
        df = pd.read_csv('source/timeline.csv', low_memory=False)
        # print(df.columns)
        # print(df.head())

        # Processing: removal of browser noise
        df = df[~df["source"].isin(["WEBHIST"])]

        # Process timestamps & mark the invalid ones
        df = processTimestamps(df)

        df.apply(deriveLinkedEntities, axis=1)
        # print(linkedEntities)

        # For the sake of checking: output to file
        output_path = os.path.join('source', 'linked_entities.json')

        # Convert to JSON and write
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(linkedEntities, f, indent=4, ensure_ascii=False)
        
        print(f"[+] Linked entities saved to: {output_path}")

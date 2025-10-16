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

def deriveLinkedEntities(row):
    """Derivation of linked entities ID based on analysis of sources"""
    src = row.get("source", "").lower().strip()
    srctype = row.get("sourcetype", "").lower().strip()
    short = row.get("short", "").lower().strip()
    inode = row.get("inode", "")
    filename = str(row.get("filename", "")).lower().strip()
    macb = row.get("MACB", "").lower().strip()
    datetime = row.get("datetime", "")
    isValidTime = row.get("is_valid_time")

    # Convert timestamp for readability
    datetime_str = datetime.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(datetime) else None

    # Anchor using $MFT entries: prefetch & MFT share the same src & srctype; can be differentiated using 'short'
    if src == "file" and srctype == "file stat" and "prefetch" not in short:
        # print(f"Found $MFT for {filename}")
        logType = "$MFT"
        
        if filename not in linkedEntities:
            linkedEntities[filename] = {}
        
        if logType not in linkedEntities[filename]:
            linkedEntities[filename][logType] = []
            
        linkedEntities[filename][logType].append({
            "datetime": datetime_str,
            "isValidTime": isValidTime,
            "shorts": short,
            "macb": macb
        })

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

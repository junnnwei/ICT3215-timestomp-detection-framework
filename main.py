import pandas as pd
import os

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


if __name__ == "__main__":
    if checkSourceFiles():
        df = pd.read_csv('source/timeline.csv', low_memory=False)
        print(df.columns)
        print(df.head())



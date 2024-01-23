# %%
import pandas as pd
import requests
from urllib.parse import urljoin

from constants import (
    HTTP_STATUS_OK,
    VALIDATION_FILE_NAME_PREFIX,
    REQUEST_URI,
    REQUEST_URI_CANONICAL,
    REDIRECT_URI,
    REDIRECT_STATUS,
    TARGET_BASE_URL,
    VALIDATION_DIR,
    VALIDATION_STATUS_FINAL,
    VALIDATION_STATUS_INITIAL,
)
from lib import errxit


def validate_redirects(base_url, csv_file):
    df = pd.read_csv(csv_file)

    mismatches = []
    for index, row in df.iterrows():
        try:
            uri = row[REQUEST_URI]
            url = urljoin(base_url, uri)

            status_initial_expected = row[REDIRECT_STATUS]
            response_initial = requests.get(url, allow_redirects=False)
            status_initial = response_initial.status_code

            response_final = requests.get(url, allow_redirects=True)
            status_final = response_final.status_code

            if status_final != HTTP_STATUS_OK:
                print(
                    f"Redirect {row[REQUEST_URI]} -> {row[REDIRECT_URI]}: initial: expected {status_initial_expected}, got {status_initial} final: {status_final}"
                )

            if status_initial != status_initial_expected:
                mismatches.append(
                    {
                        REQUEST_URI: row[REQUEST_URI],
                        REQUEST_URI_CANONICAL: row[REQUEST_URI_CANONICAL],
                        REDIRECT_URI: row[REDIRECT_URI],
                        REDIRECT_STATUS: row[REDIRECT_STATUS],
                        VALIDATION_STATUS_INITIAL: status_initial,
                        VALIDATION_STATUS_FINAL: status_final,
                    }
                )
        except requests.RequestException as e:
            print(f"Error checking {row[REQUEST_URI]}: {e}")

    return mismatches


mismatched_redirects = []
validation_files = list(VALIDATION_DIR.glob(f"{VALIDATION_FILE_NAME_PREFIX}*.csv"))
if not validation_files:
    errxit(1, f"No files found to validate")

for validation_file in validation_files:
    mismatches = validate_redirects(TARGET_BASE_URL, validation_file)
    mismatched_redirects.extend(mismatches)

# Output the results
if mismatched_redirects:
    print("Found mismatches in the following redirects:")
    for mismatch in mismatched_redirects:
        print(mismatch)
else:
    print("All redirects match the expected status codes.")

# %%

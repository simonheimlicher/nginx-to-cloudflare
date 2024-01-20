import re
import csv
from collections import defaultdict
import sys

from constants import (
    ACCESS_LOG_PROCESSED_FILE,
    ACCESS_LOG_INPUT_FILE,
    COLUMNS_ACCESS_LOG,
    INPUT_DIR,
    INTERMEDIATE_DIR,
    ORIGINAL_DOMAIN,
    REMOTE_ADDR,
    REMOTE_USER,
    REQUEST_TIMESTAMP,
    REQUEST_METHOD,
    REQUEST_URI,
    REQUEST_STATUS_CODE,
    RESPONSE_BYTES_SENT,
    REQUEST_REFERER,
    REQUEST_USER_AGENT,
)


# Updated regular expression to match all relevant fields in log entries
log_pattern = re.compile(
    r'(\d+\.\d+\.\d+\.\d+) - (\S+) \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD) (\S+) HTTP/\d\.\d" (\d{3}) (\d+) "(.*?)" "(.*?)"'
)


def process_log_file(file_path):
    logs = defaultdict(
        lambda: {
            "remote_addr": None,
            "remote_user": None,
            "datetime": None,
            "method": None,
            "path": None,
            "status_code": None,
            "body_bytes_sent": None,
            "http_referer": None,
            "http_user_agent": None,
        }
    )

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                (
                    remote_addr,
                    remote_user,
                    datetime,
                    method,
                    path,
                    status_code,
                    body_bytes_sent,
                    http_referer,
                    http_user_agent,
                ) = match.groups()
                key = (remote_addr, path)
                logs[key].update(
                    {
                        "remote_addr": remote_addr,
                        "remote_user": remote_user,
                        "datetime": datetime,
                        "method": method,
                        "path": path,
                        "status_code": status_code,
                        "body_bytes_sent": body_bytes_sent,
                        "http_referer": http_referer,
                        "http_user_agent": http_user_agent,
                    }
                )

    return logs


def write_to_csv(data, output_file):
    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(COLUMNS_ACCESS_LOG)

        for key, info in data.items():
            writer.writerow(
                [
                    info["remote_addr"],
                    info["remote_user"],
                    info["datetime"],
                    info["method"],
                    info["path"],
                    info["status_code"],
                    info["body_bytes_sent"],
                    info["http_referer"],
                    info["http_user_agent"],
                ]
            )


def main():
    if not INPUT_DIR.exists():
        sys.exit(1)

    resolved_input_dir = INPUT_DIR.resolve()
    if not resolved_input_dir.is_dir():
        sys.exit(1)

    # Ensure INTERMEDIATE_DIR exists
    INTERMEDIATE_DIR.mkdir(parents=True, exist_ok=True)
    logs = process_log_file(ACCESS_LOG_INPUT_FILE)
    write_to_csv(logs, ACCESS_LOG_PROCESSED_FILE)
    print(
        f"Access log file {ACCESS_LOG_INPUT_FILE} processed and written to {ACCESS_LOG_PROCESSED_FILE}"
    )


if __name__ == "__main__":
    main()

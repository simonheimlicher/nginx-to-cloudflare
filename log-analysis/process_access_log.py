import re
import csv
from collections import defaultdict

from constants import (
    COLUMNS_ACCESS_LOG,
)

# Regular expression to match all relevant fields in log entries
log_pattern = re.compile(
    r'(\d+\.\d+\.\d+\.\d+) - (\S+) \[(.*?)\] "(GET|POST|PUT|DELETE|HEAD) (\S+) HTTP/\d\.\d" (\d{3}) (\d+) "(.*?)" "(.*?)"'
)


def process_log_file(file_path):
    log_entry = defaultdict(
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
                log_entry[key].update(
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

    return log_entry


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

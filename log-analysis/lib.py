import logging
import re
import sys
from pathlib import Path
import traceback
from urllib.parse import urlparse

import pandas as pd

from constants import (
    COLUMN_MAP_REDIRECTS_FILE,
    COLUMNS_PROCESSING,
    HTTP_STATUS_OK,
    REDIRECTS_FILE_REDIRECT_STATUS,
    REDIRECTS_FILE_REDIRECT_URI,
    REDIRECTS_FILE_REQUEST_URI,
    REQUEST_URI,
    REDIRECT_URI,
    REDIRECT_STATUS,
    SCRIPT_PATH,
)


class Colors:
    PASTEL_YELLOW = "\033[38;5;229m"
    PASTEL_GREEN = "\033[38;5;121m"
    DARK_PASTEL_GREEN = "\033[38;5;72m"  # Darker pastel green
    AZURE_BLUE = "\033[38;5;73m"  # Darker pastel green
    DARK_PASTEL_BLUE = "\033[38;5;75m"  # Darker pastel green
    PASTEL_BLUE = "\033[38;5;117m"
    PASTEL_PINK = "\033[38;5;211m"
    PASTEL_PURPLE = "\033[38;5;183m"
    RESET = "\033[0m"


def _preprocess_output(*args, **kwargs):
    # Turn all paths into relative paths
    CWD = Path.cwd().as_posix()
    if kwargs.get("relative_paths", True):
        args = [re.sub(CWD + "/", "./", str(a)) for a in args]
    kwargs.pop("relative_paths", None)

    # Check if 'color' is specified and valid, then apply color
    color_code = kwargs.pop("color", None)
    if color_code:
        colored_message = color_code + " ".join(map(str, args)) + Colors.RESET
        return colored_message, kwargs

    return " ".join(map(str, args)), kwargs


def dbg(*args, **kwargs):
    message, kwargs = _preprocess_output(
        *args, color=Colors.DARK_PASTEL_GREEN, **kwargs
    )
    logging.getLogger().debug(message, **kwargs)


def vrb(*args, **kwargs):
    message, kwargs = _preprocess_output(*args, color=Colors.DARK_PASTEL_BLUE, **kwargs)
    logging.getLogger().info(message, **kwargs)


def wrn(*args, **kwargs):
    message, kwargs = _preprocess_output(*args, color=Colors.PASTEL_YELLOW, **kwargs)
    logging.getLogger().warning(message, **kwargs)


def errxit(status, *args):
    # Capture the exception's stack trace
    exception_info = sys.exc_info()

    # Preprocess the exception message and stack trace
    prefix = SCRIPT_PATH
    args_concat = "\n".join(map(str, args))
    if exception_info and exception_info[0] is not None:
        prefix = f"{SCRIPT_PATH}: exiting due to an unrecoverable error"
        exception_info = "".join(traceback.format_exception(*sys.exc_info()))
        args_concat = f"{prefix}\n{exception_info} {args_concat}"  # Concatenate the stack trace and additional arguments
    else:
        args_concat = f"{prefix}\n{args_concat}"

    print("".join(args_concat), file=sys.stderr, flush=True)

    # Exit the program with a non-zero status code indicating error
    sys.exit(status)


def sanitize_path_component(s, replace_with="_"):
    """
    Sanitize a string to make it safe for use as a path component in Windows, Linux, and macOS.

    :param s: The string to sanitize.
    :param replace_with: The character to replace disallowed characters with (default is '_').
    :return: The sanitized string.
    """
    # Characters disallowed in Windows filenames
    disallowed_chars_win = r'<>:"/\\|?*'

    # Control characters (0-31 and 127) are disallowed in Windows and Unix-like systems
    control_chars = "".join(map(chr, range(0, 32))) + chr(127)

    # Combine all disallowed characters into a regular expression
    disallowed_regex = re.compile(
        f"[{re.escape(disallowed_chars_win + control_chars)}]"
    )

    # Replace disallowed characters
    return disallowed_regex.sub(replace_with, s)


def diff_df(df1, df2):
    """
    Compares two dataframes and returns a dataframe with rows that are different or added.

    :param df1: First dataframe (e.g., df_canonicalized)
    :param df2: Second dataframe (e.g., df_redirects)
    :return: Dataframe containing differences and new rows
    """
    # Merge the dataframes
    merged_df = pd.merge(
        df1, df2, how="outer", indicator=True, on=None, validate="many_to_many"
    )

    # Filter to find rows that are different or only in df2
    df_differences = merged_df[merged_df["_merge"] != "both"]

    # Drop the '_merge' column
    df_differences.drop("_merge", axis=1, inplace=True)

    return df_differences


def url_without_query(url):
    # First, sanitize the URL
    # Replace multiple slashes with a single slash
    sanitized_url = re.sub(r"(?<!:)//+", "/", url)

    # Parse the sanitized URL
    parsed_url = urlparse(sanitized_url)

    # Check if the URL is a complete URL (includes a scheme like http)
    if parsed_url.scheme and parsed_url.netloc:
        return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
    elif parsed_url.path.startswith("/"):
        # If it's just a path starting with '/', return the path
        return parsed_url.path
    else:
        # Invalid URL
        return None


def ask_user_confirmation(prompt):
    """Ask the user for confirmation and return True or False based on their response."""
    response = input(prompt).strip().lower()
    return response in ["yes", "y"]


def sort_by_column_ignoring_case(df, column):
    df = df.sort_values(by=column, key=lambda x: x.str.lower(), ascending=True)
    return df


def test_substitution(df, test_set, substituted_column=REDIRECT_URI):
    for idx, test in enumerate(test_set):
        uri_test, uri_result = test
        uri_regex = r"^" + uri_test + r"$"
        redirect_match = df[
            df[REQUEST_URI].str.contains(uri_regex, na=False, case=True, regex=True)
        ]
        if redirect_match.empty:
            print(
                f'test_substitution "{uri_test}" -> {uri_result}: '
                + f"Missing redirect: no match for {uri_regex}"
            )
        elif len(redirect_match) == 1:
            redirect_row = redirect_match.iloc[0]
            row_substituted = redirect_row[substituted_column]
            if row_substituted != uri_result:
                print(
                    f'test_substitution "{uri_test}" -> {uri_result}:\n    '
                    + f"redirect_row[{substituted_column}]={row_substituted} != {uri_result}"
                )
        else:
            print(
                f'test_substitution "{uri_test}" -> {uri_result}: '
                + f"{len(redirect_match)} redirects:\n{redirect_match}"
            )


# Validate redirects against files with test cases
def validate_redirects(df_redirects, csv_file, redirects_only=False):
    df_validation = pd.read_csv(csv_file)
    expected_columns = [
        REQUEST_URI,
        REDIRECT_URI,
        REDIRECT_STATUS,
    ]

    # Check if all expected columns are in the DataFrame
    if not all(column in df_validation.columns for column in expected_columns):
        raise ValueError(
            f"CSV file {csv_file} does not contain the expected columns: {expected_columns}"
        )

    mismatches = []
    for index, test_row in df_validation.iterrows():
        error = None
        # Get all matching records from the redirects data frame
        redirect_match = df_redirects[
            df_redirects[REQUEST_URI].str.contains(
                r"^" + test_row[REQUEST_URI] + "$", na=False, case=True, regex=True
            )
        ]

        if redirects_only and test_row[REDIRECT_STATUS] == HTTP_STATUS_OK:
            # Validate that there is no redirect for this URL in df_redirects
            if not redirect_match.empty:
                # Get the first row from the matching ones
                redirect_row = redirect_match.iloc[0]
                error = (
                    f"Unwanted redirect: uri {test_row[REQUEST_URI]} has status {test_row[REDIRECT_STATUS]}\n"
                    + f"    unwanted: {redirect_row[REQUEST_URI]} -> {redirect_row[REDIRECT_URI]} {redirect_row[REDIRECT_STATUS]}"
                )
        else:
            # Validate that there a redirect for this URL in df_redirects and it is correct
            if not redirect_match.empty:
                # Get the first row from the matching ones
                redirect_row = redirect_match.iloc[0]
                if (
                    redirect_row[REDIRECT_URI] != test_row[REDIRECT_URI]
                    or redirect_row[REDIRECT_STATUS] != test_row[REDIRECT_STATUS]
                ):
                    error = (
                        f"Wrong redirect {redirect_row[REQUEST_URI]} -> {redirect_row[REDIRECT_URI]} {redirect_row[REDIRECT_STATUS]}:\n    "
                        + f"    expected: {test_row[REQUEST_URI]} -> {test_row[REDIRECT_URI]} {test_row[REDIRECT_STATUS]}"
                    )
            else:
                error = f"Missing redirect {test_row[REQUEST_URI]} -> {test_row[REDIRECT_URI]} {test_row[REDIRECT_STATUS]}"

        if error:
            print(f"{index + 1}: {error}")
            mismatches.append({"test": test_row, "redirect": redirect_match})

    return mismatches


def sort_and_order_columns(df, columns=COLUMNS_PROCESSING):
    df = sort_by_column_ignoring_case(df, REQUEST_URI)

    # Check if 'columns' is a dictionary
    if isinstance(columns, dict):
        # Check if all keys in the dictionary exist in the DataFrame
        missing_columns = set(columns.keys()) - set(df.columns)
        if missing_columns:
            raise ValueError(f"Columns not found in DataFrame: {missing_columns}")

        # Rename and reorder columns
        df = df[list(columns.keys())]
        df = df.rename(columns=columns)

    # Check if 'columns' is a list
    elif isinstance(columns, list):
        # Check if all list elements exist in the DataFrame
        missing_columns = set(columns) - set(df.columns)
        if missing_columns:
            raise ValueError(f"Columns not found in DataFrame: {missing_columns}")

        # Reorder columns
        df = df[columns]

    # Handle case where 'columns' is neither a dict nor a list
    else:
        raise TypeError("Parameter 'columns' must be a dictionary or a list")

    # Reset the index
    df = df.reset_index(drop=True)
    return df


def write_redirects_file(df, output_file, target_uri_prefix=""):
    # Extract and rename the columns required for `_redirects` file:
    #    REQUEST_URI, REDIRECT_URI, REDIRECT_STATUS
    # are renamed to OUTPUT_REQUEST_URI, OUTPUT_REDIRECT_URI, OUTPUT_REDIRECT_STATUS
    df = sort_and_order_columns(df, COLUMN_MAP_REDIRECTS_FILE)

    # Calculate the max length of values in each column
    max_length_output_request_uri = (
        df[REDIRECTS_FILE_REQUEST_URI].astype(str).map(len).max()
    )
    max_length_output_redirect_uri = (
        df[REDIRECTS_FILE_REDIRECT_URI].astype(str).map(len).max()
    )
    max_length_output_redirect_status = (
        df[REDIRECTS_FILE_REDIRECT_STATUS].astype(str).map(len).max()
    )
    length_target_prefix = len(target_uri_prefix)
    max_length_output_redirect_uri += length_target_prefix

    # Open the file for writing
    with open(output_file, "w") as file:
        for _, row in df.iterrows():
            # Format each line with appropriate spacing
            line = (
                f"{row[REDIRECTS_FILE_REQUEST_URI]:<{max_length_output_request_uri}} "
                f"{target_uri_prefix}{row[REDIRECTS_FILE_REDIRECT_URI]:<{max_length_output_redirect_uri}} "
                f"{row[REDIRECTS_FILE_REDIRECT_STATUS]:<{max_length_output_redirect_status}}\n"
            )
            file.write(line)


# %%
# Show difference between two data frames
def diff_df(df1, df2):
    """
    Compares two dataframes and returns a dataframe with rows that are different or added.

    :param df1: First dataframe (e.g., df_canonicalized)
    :param df2: Second dataframe (e.g., df_redirects)
    :return: Dataframe containing differences and new rows
    """
    # Merge the dataframes
    merged_df = pd.merge(
        df1, df2, how="outer", indicator=True, on=None, validate="many_to_many"
    )

    # Filter to find rows that are different or only in df2
    df_differences = merged_df[merged_df["_merge"] != "both"]

    # Drop the '_merge' column
    df_differences.drop("_merge", axis=1, inplace=True)

    return df_differences

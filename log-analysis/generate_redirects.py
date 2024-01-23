# %%

# Read data from aggregated nginx access log file
import re
from lib import (
    sort_and_order_columns,
    sort_by_column_ignoring_case,
    url_without_query,
)
import pandas as pd

from constants import (
    COLUMNS_COMPLETE,
    COLUMNS_FOR_ANALYSIS,
    COLUMNS_PROCESSING,
    HTTP_STATUS_NOT_FOUND,
    HTTP_STATUS_OK,
    HTTP_STATUS_REDIRECT,
    REQUEST_URI,
    REQUEST_URI_CANONICAL,
    REDIRECT_URI,
    REDIRECT_STATUS,
    ACCESS_COUNT,
    REQUEST_TIMESTAMP,
    REQUEST_URI_WITHOUT_QUERY,
)


def load_access_log(process_access_log):
    # Load the data from CSV
    df = pd.read_csv(process_access_log)
    # Convert REQUEST_DATETIME to a datetime object
    df[REQUEST_TIMESTAMP] = pd.to_datetime(
        df[REQUEST_TIMESTAMP], format="%d/%b/%Y:%H:%M:%S %z", utc=True
    )
    return df


# Consider only URLs that look valid
def filter_uris(df):
    # Ignore URLs that contain malicious code
    malicous_regex = (
        r"^/(?:admin|backup|blog|cms|console|data|debug|mailman|api|_?error)"
        + r"|\.(?:js|exe)\b"
        + r"|['\"+&]|\\x22|select*|/RK=0|/RS=\^"
        + r"|non-existing|\.well-known|81gzm|/wp[-_0-9]*|2000/00/99|/basic-tex|wordpress|2wCEAAgGBgcGB|autodiscover/|clientaccesspolicy|DbXmlInfo|php(?:unit|info)|vWfM6kbCUIv|fa3c615d773|iVBORw0KGgo"
    )
    malicious_mask = df[REQUEST_URI].str.contains(
        malicous_regex, na=False, case=False, regex=True
    )

    # Ignore URLs that contain URL-encoded characters such as %20|%23|%C3%(?:83|AE|AF|A2|82|html)|%E6%88|%22%20class=%22|...
    encoded_mask_to_ignore = df[REQUEST_URI].str.contains(
        r"%[0-9A-F]{2}", na=False, case=False, regex=True
    )
    # ...but keep URLs that contain `Page%28[^%]+%29` as those occur in URLs of the form `Page(/articles/_index.md)`
    encoded_mask_to_keep = df[REQUEST_URI].str.contains(
        r"Page%28[^%]+index\.md%29", na=False, case=False, regex=True
    )
    encoded_mask = encoded_mask_to_ignore & ~encoded_mask_to_keep

    # Ignore URLs that contain 'http:' or 'https:'...
    http_mask_to_ignore = df[REQUEST_URI].str.contains(
        r"https?:", na=False, case=False, regex=True
    )
    http_mask = http_mask_to_ignore

    # Ignore URLs that contain '.php'...
    php_mask_to_ignore = df[REQUEST_URI].str.contains(
        ".php", na=False, case=False, regex=False
    )
    # ... unless they contain 'doku.php'
    doku_php_mask_to_keep = df[REQUEST_URI].str.contains(
        "/doku.php", na=False, case=False, regex=False
    )
    php_mask = php_mask_to_ignore & ~doku_php_mask_to_keep

    # Ignore URLs that contain a file extension...
    file_extension_mask_to_ignore = df[REQUEST_URI].str.contains(
        r".", na=False, case=False, regex=False
    )
    # ...unless they ontain '.pdf' or '.md'
    file_extension_mask_to_keep = df[REQUEST_URI].str.contains(
        r"\.(?:xml|html|pdf|md)", na=False, case=False, regex=True
    )
    file_extension_mask = file_extension_mask_to_ignore & ~file_extension_mask_to_keep

    ignore_mask = (
        malicious_mask | encoded_mask | http_mask | php_mask | file_extension_mask
    )

    # Split the DataFrame into two parts: valid and invalid URLs
    # df_invalid_raw = df[ignore_mask]
    df_keep = df[~ignore_mask].copy()

    return df_keep


# Clean up the valid URLs and remove the query string
def clean_uris(df):
    # Apply the function to create a new column
    df_cleaned_raw = df
    df_cleaned_raw[REQUEST_URI_WITHOUT_QUERY] = df_cleaned_raw[REQUEST_URI].apply(
        url_without_query
    )

    # Create a mask to keep only non-None entries in REQUEST_URI_WITHOUT_QUERY
    valid_url_mask = df_cleaned_raw[REQUEST_URI_WITHOUT_QUERY].notnull()

    # Apply the mask to filter the DataFrame
    df_cleaned = df_cleaned_raw[valid_url_mask]

    # Replace column REQUEST_URI by REQUEST_URI_WITHOUT_QUERY
    # Drop the original REQUEST_URI column
    df_cleaned = df_cleaned.drop(columns=[REQUEST_URI])

    # Rename REQUEST_URI_WITHOUT_QUERY to REQUEST_URI
    df_cleaned = df_cleaned.rename(columns={REQUEST_URI_WITHOUT_QUERY: REQUEST_URI})

    # Reorder the columns
    df_cleaned = df_cleaned[COLUMNS_FOR_ANALYSIS]
    return df_cleaned.copy()


# Aggregate the cleaned URLs
def aggregate_by_request_uri(df):
    # Sort by REQUEST_URI and then by REQUEST_TIMESTAMP in descending order
    df_sorted_by_request_timestamp = df.sort_values(
        by=[REQUEST_URI, REQUEST_TIMESTAMP], ascending=[True, False]
    )

    # Create an aggregation dictionary for all columns
    aggregation_functions = {col: "first" for col in df.columns}

    # Perform the groupby and aggregation
    df_aggregated = df_sorted_by_request_timestamp.groupby(
        REQUEST_URI, as_index=False
    ).agg(aggregation_functions)

    # Create a Series with the count of each REQUEST_URI
    uri_count = df.groupby(REQUEST_URI).size()

    # Merge the count series into the aggregated DataFrame
    df_aggregated = df_aggregated.merge(uri_count.rename(ACCESS_COUNT), on=REQUEST_URI)

    # Reset the index to turn the grouped column (REQUEST_URI) back into a regular column
    df_aggregated = df_aggregated.reset_index()

    # Sort by ACCESS_COUNT from most frequent down and then by REQUEST_DATETIME from most recent down
    df_aggregated = df_aggregated.sort_values(
        by=[ACCESS_COUNT, REQUEST_TIMESTAMP], ascending=[False, False]
    ).copy()
    return df_aggregated


def apply_canonicalization(df):
    # Add a column that contains a canonicalized form of the URL
    canonicalization_rules = [
        (
            r"^/Page(?:[(]|%28)(.*)(?:(/[^./]*)|(?:/_?index\.md))(?:[)]|%29)$",
            None,
            r"\1\2/",
        ),
        (r"^(/articles/)(?:[0-9]{4}/[0-9]{2}/[0-9]{2}/)([^/]+).*$", None, r"\1\2/"),
        (r"(.*?/)(?:atom|index|start|null).*", None, r"\1"),
        (r"(.*?/)page/[1-9].*", None, r"\1"),
        (r"^/(?:hints|(?:de/)?(?:categories|series|tags))", r"_", r"-"),
        (r"(.*?)(?:/index)?\.html.*", None, r"\1/"),
        (r"(^.*/[^./]+)$", None, r"\1/"),
    ]

    def canonicalize_url(row):
        canonical_url = row[REQUEST_URI]
        # Apply all canonicalization rules in sequence
        for pattern, search_pattern, replacement in canonicalization_rules:
            if re.match(pattern, canonical_url):
                canonical_url = re.sub(
                    search_pattern if search_pattern else pattern,
                    replacement,
                    canonical_url,
                )
        return canonical_url

    # Apply the function and create 'df_canonicalized'
    df_canonicalized = df.copy()
    df_canonicalized[REQUEST_URI_CANONICAL] = df.apply(canonicalize_url, axis=1)
    df_canonicalized = sort_and_order_columns(df_canonicalized, COLUMNS_PROCESSING)
    return df_canonicalized


def apply_transformation(df):
    # Apply transformation to account for relocations of entire sections
    transformation_rules = [
        (
            r"^/(?:_media/)?(?:work/)?(?:publications/)?(dissertation|characterizing-networks|forwarding-paradigms).*",
            r"/research/\1/",
        ),
        (r"^/(?:_media/)?(?:work/)?(publications/.*)", r"/research/\1"),
    ]

    def transform_url(row):
        url = row[REQUEST_URI_CANONICAL]

        # Apply transformation rules
        for search_pattern, replacement in transformation_rules:
            if re.match(search_pattern, url):
                transformed_url = re.sub(search_pattern, replacement, url)
                return transformed_url

        return url

    # Apply the function and create 'df_redirects'
    df_transformed = df.copy()
    df_transformed[REDIRECT_URI] = df.apply(transform_url, axis=1)
    df_transformed[REDIRECT_STATUS] = HTTP_STATUS_REDIRECT

    # Filter to create 'df_transformed'
    df_transformed = df_transformed[df_transformed[REDIRECT_URI].notnull()]
    df_transformed = df_transformed[COLUMNS_COMPLETE].reset_index()
    return df_transformed


def load_hugo_uris(urls_file):
    # Get list of valid URLs and aliases from '_urls' and '_aliases' in Hugo's `public` directory
    processed_url_lines = []
    with open(urls_file, "r") as file:
        for line in file:
            # Split the line at the first unquoted '#'
            parts = line.split("#", 1)
            cleaned_line = parts[0].strip()  # Keep only the part before the '#'

            # Skip empty lines
            if cleaned_line:
                processed_url_lines.append(cleaned_line)

    # Convert the processed lines into a DataFrame
    df_hugo_valid_urls = pd.DataFrame(processed_url_lines, columns=[REQUEST_URI])
    return df_hugo_valid_urls


def load_hugo_aliases(aliases_file):
    processed_alias_lines = []
    with open(aliases_file, "r") as file:
        for line in file:
            # Split the line at the first unquoted '#'
            parts = line.split("#", 1)
            cleaned_line = parts[0].strip()  # Keep only the part before the '#'

            # Skip empty lines
            if cleaned_line:
                processed_alias_lines.append(cleaned_line)

    # Convert the processed lines into a DataFrame
    df_hugo_alias_redirects = pd.DataFrame(
        [line.split() for line in processed_alias_lines],
        columns=[REQUEST_URI, REDIRECT_URI, REDIRECT_STATUS],
    )
    return df_hugo_alias_redirects


def apply_hugo_urls_and_aliases(df, df_hugo_valid_urls, df_hugo_alias_redirects=None):
    # Apply Hugo-generated redirects based on "aliases" key in front matter of pages
    merged_redirects_list = []

    for index, row in df.iterrows():
        new_row = row.to_dict()

        # Default to no redirect, i.e., column REDIRECT_URI is `None` and status is `200`
        new_row[REDIRECT_URI] = None
        new_row[REDIRECT_STATUS] = HTTP_STATUS_OK

        # 1. Determine if the URL we try to redirect is a valid page, in which case it should not be redirected
        url_match = df_hugo_valid_urls[
            df_hugo_valid_urls[REQUEST_URI] == row[REQUEST_URI]
        ]
        if url_match.empty:
            #
            # The URL in the REQUEST_URI column is not a valid page URL
            # It still might be a valid URL for another media type
            #

            # 2. Determine if the canonical version of the URL is a valid page URL
            # If so, the URL should be redirected to its canonical version
            canonical_match = df_hugo_valid_urls[
                df_hugo_valid_urls[REQUEST_URI] == row[REQUEST_URI_CANONICAL]
            ]
            if not canonical_match.empty:
                # The URL in the REQUEST_URI_CANONICAL column is a valid URL and we should redirect to it
                new_row[REDIRECT_STATUS] = HTTP_STATUS_REDIRECT
                new_row[REDIRECT_URI] = row[REQUEST_URI_CANONICAL]
            elif not df_hugo_alias_redirects.empty:
                # Check if there is a redirect mapping from an alias in `df_hugo_alias_redirects` for the canonical URL
                alias_match = df_hugo_alias_redirects[
                    df_hugo_alias_redirects[REQUEST_URI] == row[REQUEST_URI]
                ]
                if not alias_match.empty:
                    new_row[REDIRECT_STATUS] = HTTP_STATUS_REDIRECT
                    new_row[REDIRECT_URI] = alias_match.iloc[0][
                        REDIRECT_URI
                    ]  # First matching record's Redirect URL
                else:
                    # 3. Determine if the current redirect URL is a valid URL and the original URL should be redirected
                    redirect_match = df_hugo_valid_urls[
                        df_hugo_valid_urls[REQUEST_URI] == row[REDIRECT_URI]
                    ]
                    if not redirect_match.empty:
                        #  Current redirect URL is valid as the URL exists in df_hugo_valid_urls
                        new_row[REDIRECT_STATUS] = HTTP_STATUS_REDIRECT
                        new_row[REDIRECT_URI] = row[REDIRECT_URI]
                    else:
                        # Check if there is a redirect mapping from an alias in `df_hugo_alias_redirects` for the canonical URL
                        canonical_alias_match = df_hugo_alias_redirects[
                            df_hugo_alias_redirects[REQUEST_URI]
                            == row[REQUEST_URI_CANONICAL]
                        ]
                        if not canonical_alias_match.empty:
                            new_row[REDIRECT_STATUS] = HTTP_STATUS_REDIRECT
                            new_row[REDIRECT_URI] = canonical_alias_match.iloc[0][
                                REDIRECT_URI
                            ]  # First matching record's Redirect URL
                        else:
                            redirect_alias_match = df_hugo_alias_redirects[
                                df_hugo_alias_redirects[REQUEST_URI]
                                == row[REDIRECT_URI]
                            ]
                            if not redirect_alias_match.empty:
                                new_row[REDIRECT_STATUS] = HTTP_STATUS_REDIRECT
                                new_row[REDIRECT_URI] = redirect_alias_match.iloc[0][
                                    REDIRECT_URI
                                ]  # First matching record's Redirect URL
                            else:
                                # No page to redirect to found.
                                # If the URL corresponds to a file, we blindly redirect
                                if (
                                    re.match(
                                        r".*\.[a-z0-9]+$",
                                        row[REQUEST_URI_CANONICAL],
                                        flags=re.IGNORECASE,
                                    )
                                    and row[REDIRECT_URI] != row[REQUEST_URI]
                                ):
                                    new_row[REDIRECT_STATUS] = HTTP_STATUS_REDIRECT
                                    new_row[REDIRECT_URI] = row[REDIRECT_URI]
                                else:
                                    # Redirect to the canonical URL as all the default rules below are based on canonical URLs
                                    new_row[REDIRECT_STATUS] = HTTP_STATUS_NOT_FOUND
                                    new_row[REDIRECT_URI] = row[REQUEST_URI_CANONICAL]

        # Append the new row to the list
        merged_redirects_list.append(new_row)

    # Convert the list of dictionaries to a DataFrame
    df_merged_redirects = pd.DataFrame(merged_redirects_list)
    return df_merged_redirects


def apply_default_redirects(df):
    # Redirect a selection of obsoleted URLs to the most relevant category or section to avoid 404 errors
    default_rules = [
        (r"^/private/.*", r"/about/"),
        (
            r"^/articles.*time-machine-volume-uuid.*",
            r"/technology/time-machine-volume-uuid/",
        ),
        (
            r"^/articles.*time-machine.*",
            r"/technology/time-machine-inherit-backup-using-tmutil/",
        ),
        (r"^/public/tips/macosx/.*", r"/technology/"),
        (r"^/(?:work|software)/.*", r"/technology/"),
        (r"^/hints/macosx(?:/server)?.*", r"/technology/"),
        (r"^/hints.*", r"/technology/"),
        (
            r"^/tags/(?:ios|ipad|matlab|nginx|perl|programming|time-machine).*",
            r"/technology/",
        ),
        (r"^/articles/os-x.*", r"/technology/"),
        (r"^/articles/style.*", r"/digitization/"),
        (r"^/articles/.*", r"/technology/"),
        (r"^/tool/.*", r"/technology/"),
    ]

    def default_url(row):
        redirect_uri = row[REDIRECT_URI]
        redirect_status = row[REDIRECT_STATUS]

        if redirect_status == HTTP_STATUS_NOT_FOUND:
            canonical_uri = row[REQUEST_URI_CANONICAL]

            # Apply transformation rules
            for search_pattern, replacement in default_rules:
                if re.match(search_pattern, canonical_uri):
                    redirect_uri = re.sub(search_pattern, replacement, canonical_uri)
                    redirect_status = HTTP_STATUS_REDIRECT
                    return pd.Series([redirect_uri, redirect_status])

        return pd.Series([redirect_uri, redirect_status])

    df_defaulted_redirects = df.copy()
    df_defaulted_redirects[
        [REDIRECT_URI, REDIRECT_STATUS]
    ] = df_defaulted_redirects.apply(default_url, axis=1, result_type="expand")
    # Ensure that column `Redirect Status` contains only integers
    df_defaulted_redirects[REDIRECT_STATUS] = df_defaulted_redirects[
        REDIRECT_STATUS
    ].astype(int)
    return df_defaulted_redirects


def finalize_redirects(df, target_uri_prefix=""):
    redirect_required_mask = df[REDIRECT_STATUS] == HTTP_STATUS_REDIRECT
    df_redirects_required = df[redirect_required_mask]

    # If we are redirecting to a different target URL, we also include all valid URIs
    # as required redirects as those need to be redirected to the new base URL as well
    if target_uri_prefix:
        # Store URIs that still exist for later validation that no redirect occurs
        redirects_to_existing_mask = df[REDIRECT_STATUS] == HTTP_STATUS_OK
        df_redirects_to_existing = df[redirects_to_existing_mask].copy()
        df_redirects_to_existing.loc[:, REDIRECT_URI] = df_redirects_to_existing[
            REQUEST_URI
        ]

        df_redirects_complete = pd.concat(
            [df_redirects_required, df_redirects_to_existing], ignore_index=True
        )
    else:
        df_redirects_complete = df_redirects_required
    return df_redirects_complete, df_redirects_to_existing


def get_recent_frequent_redirects(df, year=2021, count=10):
    # Prepare data frame with recent and frequent redirects
    df_recent_frequent = df.copy()

    # Accessed since the given year or later...
    df_recent_frequent = df_recent_frequent[
        df_recent_frequent[REQUEST_TIMESTAMP].dt.year >= year
    ]
    # ... at least count times
    df_recent_frequent = df_recent_frequent[df_recent_frequent[ACCESS_COUNT] > count]
    return df_recent_frequent


def generate_validation_data(
    df_redirects_to_existing, df_required_recent_frequent_redirects
):
    # Create validation data comprising:
    # 1. All existing URIs to make sure no redirect exists
    # 2. Recent and frequent required redirects to make sure a redirect exists

    # Concatenate all existing URIs with recent and frequent redirects
    df_redirects_validation = pd.concat(
        [df_redirects_to_existing, df_required_recent_frequent_redirects],
        ignore_index=True,
    )

    # Reset index
    df_redirects_validation.reset_index(drop=True, inplace=True)

    df_redirects_validation = sort_by_column_ignoring_case(
        df_redirects_validation, REQUEST_URI
    )
    return df_redirects_validation


def get_complete_recent_frequent_redirects(
    df_redirects_to_existing,
    df_required_recent_frequent_redirects,
    target_uri_prefix="",
):
    # Concatenate all existing URIs with recent and frequent redirects
    if target_uri_prefix:
        #
        df_redirects_to_existing_target = df_redirects_to_existing.copy()
        df_redirects_to_existing_target[REDIRECT_STATUS] = HTTP_STATUS_REDIRECT
        df_complete_recent_frequent_redirects = pd.concat(
            [df_redirects_to_existing_target, df_required_recent_frequent_redirects],
            ignore_index=True,
        )
        # Reset index
        df_complete_recent_frequent_redirects.reset_index(drop=True, inplace=True)

        df_complete_recent_frequent_redirects = sort_by_column_ignoring_case(
            df_complete_recent_frequent_redirects, REQUEST_URI
        )
    else:
        df_complete_recent_frequent_redirects = df_required_recent_frequent_redirects
    return df_complete_recent_frequent_redirects

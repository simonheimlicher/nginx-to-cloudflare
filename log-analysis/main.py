from constants import (
    HTTP_STATUS_NOT_FOUND,
    HTTP_STATUS_OK,
    HTTP_STATUS_REDIRECT,
    REDIRECT_STATUS,
    RESPONSE_STATUS,
    VALIDATION_FILE_NAME_PREFIX,
)

from lib import (
    ask_user_confirmation,
    errxit,
    validate_redirects,
    vrb,
    write_redirects_file,
)
from config import (
    get_config,
    parse_arguments,
)

from process_access_log import process_log_file, write_to_csv
from generate_redirects import (
    apply_canonicalization,
    apply_default_redirects,
    apply_hugo_urls_and_aliases,
    finalize_redirects,
    generate_validation_data,
    get_complete_recent_frequent_redirects,
    get_recent_frequent_redirects,
    load_access_log,
    aggregate_by_request_uri,
    clean_uris,
    filter_uris,
    load_hugo_aliases,
    load_hugo_uris,
    apply_transformation,
)


def main():
    args = parse_arguments()
    # Iterate over all access log file as the source of request URIs
    for index, access_log in enumerate(args["access_log_files"]):
        if not access_log.exists():
            errxit(1, f"Input file / directory {access_log} does not exist")

        if index:
            vrb("")

        config = get_config(args, access_log)

        intermediate_access_log_processed = config["intermediate_access_log_processed"]
        # Ensure directory for intermediate and output files exists
        config["intermediate_dir"].mkdir(parents=True, exist_ok=True)
        config["output_dir"].mkdir(parents=True, exist_ok=True)

        #
        # Parse log file into a CSV file
        #

        logs = process_log_file(access_log)
        write_to_csv(logs, intermediate_access_log_processed)
        vrb(
            "Processing access log file "
            + str(access_log)
            + "\nProcessed access log file written to "
            + str(intermediate_access_log_processed)
        )

        #
        # Process CSV file
        #

        # Load the data from CSV
        df_initial = load_access_log(intermediate_access_log_processed)
        df_filtered = filter_uris(df_initial)
        df_cleaned = clean_uris(df_filtered)
        df_aggregated = aggregate_by_request_uri(df_cleaned)
        if args["debug"]:
            # Output aggregated URIs to CSV file
            df_aggregated.to_csv(
                config["intermediate_aggregated_uris_file"], index=False
            )

        df_canonicalized = apply_canonicalization(df_aggregated)
        df_accesslog_redirects = apply_transformation(df_canonicalized)
        df_accesslog_redirects.to_csv(
            config["intermediate_redirects_from_rules_file"], index=False
        )
        if (
            config["input_hugo_generated_urls_file"]
            and config["input_hugo_generated_urls_file"].exists()
        ):
            df_hugo_valid_uris = load_hugo_uris(
                config["input_hugo_generated_urls_file"]
            )
            if (
                config["input_hugo_generated_aliases_file"]
                and config["input_hugo_generated_aliases_file"].exists()
            ):
                df_hugo_aliases = load_hugo_aliases(
                    config["input_hugo_generated_aliases_file"]
                )
            else:
                df_hugo_aliases = None
            df_accesslog_hugo_redirects = apply_hugo_urls_and_aliases(
                df_accesslog_redirects, df_hugo_valid_uris, df_hugo_aliases
            )
        else:
            df_accesslog_hugo_redirects = df_accesslog_redirects

        df_defaulted_redirects = apply_default_redirects(df_accesslog_hugo_redirects)

        df_complete_redirects, df_redirects_to_existing = finalize_redirects(
            df_defaulted_redirects,
            args["target_uri_prefix"],
        )

        # Validate against test cases
        mismatched_redirects = []
        # Convert to list to check if it's empty
        validation_files = list(
            config["validation_dir"].glob(f"{VALIDATION_FILE_NAME_PREFIX}*.csv")
        )
        if validation_files:
            for validation_file in validation_files:
                mismatches = validate_redirects(df_complete_redirects, validation_file)
                mismatched_redirects.extend(mismatches)

        # Write the DataFrame to a CSV file
        df_complete_redirects.to_csv(
            config["intermediate_complete_redirects_file"], index=False
        )

        df_recent_frequent_redirects = get_recent_frequent_redirects(
            df_complete_redirects
        )

        df_required_recent_frequent_redirects = df_recent_frequent_redirects[
            df_recent_frequent_redirects[REDIRECT_STATUS] == HTTP_STATUS_REDIRECT
        ]

        df_validation = generate_validation_data(
            df_redirects_to_existing, df_required_recent_frequent_redirects
        )
        df_validation.to_csv(config["output_redirects_validation_file"])
        vrb(
            f"Proposal for validation file written to {config["output_redirects_validation_file"]}"
        )

        df_final = get_complete_recent_frequent_redirects(
            df_redirects_to_existing,
            df_required_recent_frequent_redirects,
            args["target_uri_prefix"],
        )

        # Write the DataFrame to a `_redirects` file for use by Netlify, Cloudflare etc.
        write_redirects_file(
            df_final,
            config["output_netlify_redirects_file"],
            args["target_uri_prefix"],
        )
        vrb(
            f"Redirects file for Netlify or Cloudflare Pages written to {config["output_netlify_redirects_file"]}"
        )

        # Write the DataFrame to a CSV file for manual inspection (easier to read than JSON)
        df_final.to_csv(
            config["intermediate_hugo_data_redirects_csv_file"], index=False
        )

        # Write the DataFrame to a JSON file in Hugo's `data` directory to enable
        # Hugo to generate an up-to-date `_redirects` file via the template `layouts/index.redir`
        df_final.to_json(
            config["output_hugo_data_redirects_json_file"], orient="records"
        )

        # Output redirects to invalid URLs to CSV file
        invalid_redirects_mask = df_final[REDIRECT_STATUS] == HTTP_STATUS_NOT_FOUND
        if any(invalid_redirects_mask):
            df_redirects_invalid = df_final[invalid_redirects_mask]

            df_redirects_invalid.to_csv(
                config["output_redirects_to_invalid_file"], index=False
            )

        # Output redirects to valid URLs, which must not be redirected, to CSV file
        url_was_valid_mask = df_final[RESPONSE_STATUS] == HTTP_STATUS_OK
        url_is_valid_mask = df_final[REDIRECT_STATUS] == HTTP_STATUS_OK
        unwanted_redirects_mask = url_was_valid_mask & url_is_valid_mask
        if any(unwanted_redirects_mask):
            df_redirects_unwanted = df_final[unwanted_redirects_mask]

            df_redirects_unwanted.to_csv(
                config["output_redirects_to_existing_file"], index=False
            )

        if (
            len(mismatched_redirects) == 0
            and config["output_to_hugo_data_redirects_json_file"]
        ):
            if not config[
                "output_to_hugo_data_redirects_json_file"
            ].exists() or ask_user_confirmation(
                "The generated Hugo redirects JSON file already exists at \n"
                + str(config["output_to_hugo_data_redirects_json_file"])
                + "\n\nConfirm overwriting it with the new file\n    "
                + str(config["intermediate_hugo_data_redirects_csv_file"])
                + "\n(yes/NO): "
            ):
                try:
                    config["output_hugo_data_redirects_json_file"].rename(
                        config["output_to_hugo_data_redirects_json_file"]
                    )
                    print(
                        f"File moved to {config["output_to_hugo_data_redirects_json_file"]}"
                    )
                except Exception as e:
                    errxit(1, f"An error occurred while moving the file: {e}")


if __name__ == "__main__":
    main()

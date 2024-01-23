import logging
import os
import sys
from pathlib import Path
from urllib.parse import urlparse, urlunparse
import dotenv


from constants import (
    HUGO_GENERATED_ALIASES_FILE,
    HUGO_GENERATED_URLS_FILE,
    INTERMEDIATE_DIR,
    OUTPUT_DIR,
    VALIDATION_DIR,
)
from lib import dbg, errxit, sanitize_path_component


# Initialize logging
def initialize_logging(level=logging.WARN):
    # logging.basicConfig(format="%(levelname)s:  %(message)s", level=logging.NOTSET)
    logging.basicConfig(format="%(message)s", level=logging.NOTSET)
    logger = logging.getLogger()
    logger.setLevel(level)
    # Set the logging level for asyncio to WARNING to suppress informational messages
    logging.getLogger("asyncio").setLevel(logging.WARNING)


# Parse command line arguments
def parse_arguments():
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate _redirects file for Netlify, Cloudflare Pages etc."
    )
    parser.add_argument("--root-dir", "-r", type=Path, default=None, help="Root dir")
    parser.add_argument(
        "--hugo-data-dir",
        type=Path,
        default=None,
        help="Hugo data directory to put generated redirects file",
    )
    parser.add_argument(
        "--original", default=None, help="The hostname of the original website"
    )
    parser.add_argument("--original-base-url", default="", help="The original base URL")
    parser.add_argument(
        "--target", default="", help="The hostname to construct the target base URL"
    )
    parser.add_argument("--target-base-url", default="", help="The target base URL")
    parser.add_argument(
        "--prefix", default="", help="Prefix for file names of generated files"
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--debug", action="store_true", help="Debug output")
    parser.add_argument(
        "--dry-run",
        "-n",
        action="store_true",
        help="Only output commands without actually running them",
    )

    parser.add_argument(
        "logfiles",
        type=str,
        nargs="*",
        default=None,
        help="<LOG FILE 1> [<LOG FILE 2>]",
    )

    # Parse the arguments
    args = parser.parse_args()

    # Load the .env file
    dotenv.load_dotenv(override=True, verbose=True)

    loglevel = logging.ERROR
    if args.debug or os.getenv("DEBUG"):
        loglevel = logging.DEBUG
    elif args.verbose or os.getenv("VERBOSE"):
        loglevel = logging.INFO
    initialize_logging(loglevel)

    if args.logfiles:
        logfiles_str = args.logfiles
        logfile_str_src = f"arguments {logfiles_str}"
    elif os.getenv("LOGFILES"):
        logfiles_str = [os.getenv("LOGFILES")]
        logfile_str_src = f"environment variable LOGFILES='{logfiles_str}'"
    else:
        errxit(
            1,
            "Please provide one or more access log files as "
            + "arguments or via environment variable LOGFILES",
        )

    logfile_paths = []
    for logfile in logfiles_str:
        logfile_path = Path(logfile)
        if not logfile_path.is_absolute():
            logfile_path = Path(os.getcwd()) / logfile
        if logfile_path.exists():
            if logfile_path.is_dir():
                logfile_paths.extend(
                    [Path(f).resolve() for f in logfile_path.glob("**/*.log")]
                )
            else:
                logfile_paths.append(logfile_path.resolve())

    if not logfile_paths:
        errxit(
            1,
            "The log files provided via " + logfile_str_src + " do not exist",
        )

    original_hostname = args.original or os.getenv("ORIGINAL_HOSTNAME", None)
    # Gather or construct the original base URL
    original_base_url = args.original_base_url or os.getenv("ORIGINAL_BASE_URL", None)
    if not original_base_url:
        original_base_url = urlunparse(("https", original_hostname, "/", "", "", ""))

    target_hostname = args.target or os.getenv("TARGET_HOSTNAME", None)

    # Gather or construct the target base URL
    target_base_url = args.target_base_url or os.getenv("TARGET_BASE_URL", None)
    if not target_hostname and not target_base_url:
        target_hostname = original_hostname
    if target_hostname and not target_base_url:
        target_base_url = urlunparse(("https", target_hostname, "/", "", "", ""))
    if not target_hostname and target_base_url:
        target_hostname = urlparse(target_base_url).hostname
    target_uri_prefix = target_base_url if target_hostname != original_hostname else ""

    root_dir = args.root_dir.resolve() if args.root_dir else None
    generated_directory_prefix = (
        sanitize_path_component(original_hostname) if original_hostname else None
    )
    if target_hostname:
        if generated_directory_prefix:
            generated_directory_prefix = sanitize_path_component(
                f"{generated_directory_prefix}_to_{target_hostname}"
            )
        else:
            generated_directory_prefix = sanitize_path_component(
                f"to_{target_hostname}"
            )

    generated_file_prefix = sanitize_path_component(args.prefix) if args.prefix else ""

    # Return all the constants
    params = {
        "root_dir": root_dir,
        "access_log_files": logfile_paths,
        "original_hostname": original_hostname,
        "original_base_url": original_base_url,
        "target_hostname": target_hostname,
        "target_base_url": target_base_url,
        "target_uri_prefix": target_uri_prefix,
        "generated_directory_prefix": generated_directory_prefix,
        "generated_file_prefix": generated_file_prefix,
        "verbose": args.verbose,
        "debug": args.debug,
        "dry_run": args.dry_run,
    }
    dbg(
        f"Parameters from arguments\n    {[a for a in sys.argv[1:]]}\nand environment:",
        params,
    )
    return params


def get_config(args, access_log):
    root_dir = args["root_dir"] if args["root_dir"] else access_log.parent
    if args["generated_directory_prefix"]:
        root_dir = root_dir / args["generated_directory_prefix"]
    validation_dir = root_dir / VALIDATION_DIR

    intermediate_dir = root_dir / INTERMEDIATE_DIR
    output_dir = root_dir / OUTPUT_DIR

    intermediate_access_log_processed = (
        intermediate_dir / "intermediate_access_log_processed.csv"
    )

    intermediate_aggregated_uris_file = (
        output_dir / f"{args['generated_file_prefix']}uris.csv"
    )

    # Redirects generated by rules in `generate-redirects.py`
    intermediate_redirects_from_rules_file = (
        output_dir / f"{args['generated_file_prefix']}redirects_from_log.csv"
    )

    # Complete list of redirects, comprising both
    # - Redirects from rules in `generate-redirects.py`
    # - Redirects generated by Hugo based on "aliases" key in front matter of pages
    intermediate_complete_redirects_file = (
        output_dir / f"{args['generated_file_prefix']}redirects_complete.csv"
    )

    # Complete list of URLs and redirects, comprising both
    # - Redirects from rules in `generate-redirects.py`
    # - Redirects generated by Hugo based on "aliases" key in front matter of pages
    # - Valid URIs generated by Hugo indicating that redirects must not be generated
    output_redirects_validation_file = (
        output_dir / f"{args['generated_file_prefix']}redirects_validation.csv"
    )

    # Redirects to URIs that are not generated by Hugo
    # These redirects must be changed to point to URIs that Hugo generates
    output_redirects_to_invalid_file = (
        output_dir / f"{args['generated_file_prefix']}redirects_invalid.csv"
    )

    # Redirects to URIs that are actually generated by Hugo
    # These redirects must be deleted to avoid shadowing valid URIs from HUGO
    output_redirects_to_existing_file = (
        output_dir / f"{args['generated_file_prefix']}redirects_unwanted.csv"
    )

    output_netlify_redirects_file = (
        output_dir / f"{args['generated_file_prefix']}_redirects"
    )

    intermediate_hugo_data_redirects_csv_file = (
        output_dir / f"{args['generated_file_prefix']}hugo_data_redirects.csv"
    )

    # File in Hugo's data directory that provides Hugo with the redirects generated based on the historical access log
    output_hugo_data_redirects_json_file = (
        output_dir / f"{args['generated_file_prefix']}hugo_data_redirects.json"
    )

    # Required input: complete list of URIs generated by Hugo
    input_hugo_generated_urls_file = None
    # Optional input: list of alias mappings generated by Hugo
    input_hugo_generated_aliases_file = None
    # The above file needs to be moved into the Hugo data dir at the following location
    output_to_hugo_data_redirects_json_file = None
    hugo_project_dir_str = os.getenv("HUGO_PROJECT_DIR", None)
    if hugo_project_dir_str:
        hugo_output_sub_path = os.getenv("HUGO_OUTPUT_SUB_PATH", "public")
        hugo_data_sub_path = os.getenv("HUGO_DATA_SUB_PATH", "data")
        hugo_project_dir_path = Path(hugo_project_dir_str).resolve()
        hugo_public_dir = hugo_project_dir_path / hugo_output_sub_path
        hugo_data_dir = hugo_project_dir_path / hugo_data_sub_path

        # Required input: complete list of URIs generated by Hugo
        input_hugo_generated_urls_file = hugo_public_dir / HUGO_GENERATED_URLS_FILE
        # Optional input: list of alias mappings generated by Hugo
        input_hugo_generated_aliases_file = (
            hugo_public_dir / HUGO_GENERATED_ALIASES_FILE
        )
        # The above file needs to be moved into the Hugo data dir at the following location
        # However, this does only make sense if we are operating on a single log file,
        # otherwise this file will be written to multiple times
        if len(args["access_log_files"]) == 1:
            output_to_hugo_data_redirects_json_file = hugo_data_dir / "redirects.json"

    return {
        "root_dir": root_dir,
        "validation_dir": validation_dir,
        "input_hugo_generated_urls_file": input_hugo_generated_urls_file,
        "input_hugo_generated_aliases_file": input_hugo_generated_aliases_file,
        "intermediate_dir": intermediate_dir,
        "intermediate_access_log_processed": intermediate_access_log_processed,
        "intermediate_aggregated_uris_file": intermediate_aggregated_uris_file,
        "intermediate_redirects_from_rules_file": intermediate_redirects_from_rules_file,
        "intermediate_complete_redirects_file": intermediate_complete_redirects_file,
        "intermediate_hugo_data_redirects_csv_file": intermediate_hugo_data_redirects_csv_file,
        "output_dir": output_dir,
        "output_redirects_validation_file": output_redirects_validation_file,
        "output_redirects_to_invalid_file": output_redirects_to_invalid_file,
        "output_redirects_to_existing_file": output_redirects_to_existing_file,
        "output_netlify_redirects_file": output_netlify_redirects_file,
        "output_hugo_data_redirects_json_file": output_hugo_data_redirects_json_file,
        "output_to_hugo_data_redirects_json_file": output_to_hugo_data_redirects_json_file,
    }

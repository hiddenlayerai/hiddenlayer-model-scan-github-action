import argparse
import os
import sys
import uuid
from pathlib import Path
from typing import Optional
import json

from hiddenlayer import HiddenlayerServiceClient
from urllib.parse import urlparse

import markdown
import sarif


# From the deprecated disutils package that used to be apart of the stdlib
def strtobool(val):
    """Convert a string representation of truth to true (1) or false (0).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return 1
    elif val in ("n", "no", "f", "false", "off", "0"):
        return 0
    else:
        raise ValueError("invalid truth value %r" % (val,))


def main(
    model_path: str,
    api_url: str = "https://api.us.hiddenlayer.ai",
    fail_on_detection: bool = True,
    output_file: Optional[str] = None,
    sarif_file: Optional[str] = None,
):
    """
    Scans a model using the HiddenLayer API.

    Currently supported scan locations are files on disk or s3.
    """
    hl_api_id = os.getenv("HL_CLIENT_ID")
    hl_api_key = os.getenv("HL_CLIENT_SECRET")

    # Run "state of the world checks"
    # Fail on stuff like invalid params, unwriteable paths early
    # so users don't run a entire scan just to have it fail on something
    # we could have checked for

    # If the output file doesn't end in json or it's a dir, error early
    if output_file and (
        Path(output_file).is_dir() or not output_file.endswith(".json")
    ):
        raise ValueError("Output file must be a json file, i.e `output.json`")

    if output_file:
        if not os.access(Path(output_file).absolute().parent, os.W_OK):
            raise IOError(
                f"The current user does not have permissions to write to {Path(output_file).absolute()}"
            )

    if sarif_file:
        if not os.access(Path(sarif_file).absolute().parent, os.W_OK):
            raise IOError(
                f"The current user does not have permissions to write to {Path(sarif_file).absolute()}"
            )

    # Client inits
    hl_client = HiddenlayerServiceClient(
        host=api_url, api_id=hl_api_id, api_key=hl_api_key
    )

    markdown_generator = markdown.MarkdownStringGenerator()
    markdown_generator.h2("Model Scanner Results")
    markdown_generator.create_table(["File Name", "Result"])

    if model_path.startswith("s3://"):
        bucket, key = model_path.split("/", 2)[-1].split("/", 1)
        file = key.split("/")[-1]

        scan_results = hl_client.model_scanner.scan_s3_model(
            model_name=file, bucket=bucket, key=key
        )

        all_scan_results = [scan_results]
    elif model_path.startswith("https://") and "blob.core.windows.net" in model_path:
        parsed_url = urlparse(model_path)

        account_url = f"{parsed_url.scheme}://{parsed_url.hostname}"
        container, blob = parsed_url.path.removeprefix("/").split("/", maxsplit=1)

        scan_results = hl_client.model_scanner.scan_azure_blob_model(
            model_name=blob,
            account_url=account_url,
            container=container,
            blob=blob,
            credential=os.getenv("AZURE_BLOB_SAS_KEY"),
        )

        all_scan_results = [scan_results]
    elif model_path.startswith("hf://"):
        all_scan_results = hl_client.model_scanner.scan_huggingface_model(
            repo_id=model_path.removeprefix("hf://"),
            hf_token=os.getenv("HUGGINGFACE_TOKEN"),
        )
    elif Path(model_path).is_dir():
        all_scan_results = hl_client.model_scanner.scan_folder(path=Path(model_path))
    else:
        model_path: Path = Path(model_path)
        all_scan_results = [
            hl_client.model_scanner.scan_file(
                model_name=model_path.name, model_path=model_path
            )
        ]

    detected = False  # Whether we detected a malicious file during the scans

    for scan_result in all_scan_results:
        if scan_result.detections:
            detected = True
            markdown_generator.add_table_row([str(scan_result.file_path), ":x:"])
        else:
            markdown_generator.add_table_row(
                [str(scan_result.file_path), ":white_check_mark:"]
            )

    if os.environ.get("GITHUB_OUTPUT"):
        name = "detection_results"

        with open(os.environ["GITHUB_OUTPUT"], "a") as f:
            delimiter = uuid.uuid1()
            print(f"{name}<<{delimiter}", file=f)
            print(markdown_generator.markdown_string, file=f)
            print(delimiter, file=f)

    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            print(markdown_generator.markdown_string.replace("\\n", "\n"), file=f)

    json_output = [res.to_dict() for res in all_scan_results]
    print(json.dumps(json_output, indent=4))

    if output_file:
        with open(output_file, "w") as f:
            json.dump(json_output, f, indent=4)

    if sarif_file:
        sarif_output = sarif.SarifV2Output.from_scan_results(all_scan_results)
        with open(sarif_file, "w") as f:
            json.dump(sarif_output.model_dump(by_alias=True), f, indent=4)

    if detected and fail_on_detection:
        print("Malicious models found!")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Model Scanner")
    parser.add_argument("model_path", type=str)
    parser.add_argument("api_url", type=str)
    parser.add_argument("output_file", type=str)
    parser.add_argument("sarif_file", type=str)
    parser.add_argument("--fail-on-detection", action="store_true", required=False)

    # Since this is running from a Github action, if there are 5 total args to the program
    # there will always be 5 inputs to the program.
    # Ex python3 model_scan.py ./model_path https://... output.json output.sarif
    # will get translated to:
    #   (model_path, https://..., output.json, output.sarif, '')
    # `parse_known_args` allows there to be trailing args while allowing us to safely
    # get the args we want from the input
    args = parser.parse_known_args()

    main(
        args[0].model_path,
        args[0].api_url,
        args[0].fail_on_detection,
        args[0].output_file,
        args[0].sarif_file,
    )

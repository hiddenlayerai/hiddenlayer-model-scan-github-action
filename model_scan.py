import argparse
import os
import sys
import uuid
from pathlib import Path
from typing import Optional
import json

from hiddenlayer import HiddenlayerServiceClient
from hiddenlayer.sdk.constants import CommunityScanSource
from urllib.parse import urlparse

import markdown

def make_github_compatible_sarif(sarif: str) -> str:
    # deserialize the json
    sarif_json = json.loads(sarif)
    # iterate all runs
    for i, run in enumerate(sarif_json["runs"]):
        # iterate all results
        for j, result in enumerate(run["results"]):
            # iterate all locations
            for k, location in enumerate(result["locations"]):
                uriStr = location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
                if uriStr:
                    # replace the uri protocol with file://
                    uri = urlparse(uriStr)
                    uri = uri._replace(scheme="file")
                    sarif_json["runs"][i]["results"][j]["locations"][k]["physicalLocation"]["artifactLocation"]["uri"] = uri.geturl()
    return json.dumps(sarif_json)

def main(
    model_path: str,
    api_url: str = "https://api.us.hiddenlayer.ai",
    fail_on_detection: bool = True,
    output_file: Optional[str] = None,
    sarif_file: Optional[str] = None,
    run_id: Optional[str] = None,
    model_name: Optional[str] = None,
    community_scan: Optional[CommunityScanSource] = None,
    model_version: Optional[str] = None,
):
    """
    Scans a model using the HiddenLayer API.

    Currently supported scan locations are files on disk or s3.
    """
    hl_api_id = os.getenv("HL_CLIENT_ID")
    hl_api_key = os.getenv("HL_CLIENT_SECRET")

    model_name = model_name or model_path

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

    if community_scan is not None:
        if model_version is None:
            if community_scan == CommunityScanSource.HUGGING_FACE:
                model_version = "main"
            else:
                raise ValueError(
                    "When running a community scan other than a Hugging Face model, you must provide a model version."
                )
        # intentionally handle this case before the others, to bypass legacy "community scan" style scans
        scan_result = hl_client.model_scanner.community_scan(
            model_name=model_name,
            model_path=model_path,
            model_source=community_scan,
            model_version=model_version,
        )
    elif model_path.startswith("s3://"):
        bucket, key = model_path.split("/", 2)[-1].split("/", 1)
        scan_result = hl_client.model_scanner.scan_s3_model(
            model_name=model_name, bucket=bucket, key=key
        )

    elif model_path.startswith("https://") and "blob.core.windows.net" in model_path:
        parsed_url = urlparse(model_path)

        account_url = f"{parsed_url.scheme}://{parsed_url.hostname}"
        container, blob = parsed_url.path.removeprefix("/").split("/", maxsplit=1)

        scan_result = hl_client.model_scanner.scan_azure_blob_model(
            model_name=model_name,
            account_url=account_url,
            container=container,
            blob=blob,
            credential=os.getenv("AZURE_BLOB_SAS_KEY"),
        )
    elif model_path.startswith("hf://"):
        scan_result = hl_client.model_scanner.scan_huggingface_model(
            repo_id=model_path.removeprefix("hf://"),
            hf_token=os.getenv("HUGGINGFACE_TOKEN"),
            model_name=model_name,
        )
    elif Path(model_path).is_dir():
        scan_result = hl_client.model_scanner.scan_folder(
            path=Path(model_path), model_name=model_name
        )
    else:
        model_path: Path = Path(model_path)
        scan_result = hl_client.model_scanner.scan_file(
            model_name=model_name, model_path=model_path
        )

    detected = False  # Whether we detected a malicious file during the scans

    if scan_result.detection_count > 0:
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

    json_output = scan_result.to_dict()
    print(json.dumps(json_output, indent=4, default=str))

    if output_file:
        with open(output_file, "w") as f:
            json.dump(json_output, f, indent=4, default=str)

    if sarif_file:
        sarif_output = hl_client.model_scanner.get_sarif_results(
            scan_id=scan_result.scan_id
        )
        sarif_output = make_github_compatible_sarif(sarif_output)
        with open(sarif_file, "w") as f:
            f.write(sarif_output)

    if detected and fail_on_detection:
        print("Malicious models found!")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Model Scanner")
    parser.add_argument("model_path", type=str)
    parser.add_argument("api_url", type=str)
    parser.add_argument("output_file", type=str)
    parser.add_argument("sarif_file", type=str)
    parser.add_argument("run_id", type=str)
    parser.add_argument("model_name", type=str)
    parser.add_argument("--model_version", type=str, required=False, default=None)
    parser.add_argument("--community_scan", type=CommunityScanSource, required=False)
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
        args[0].run_id,
        args[0].model_name,
        args[0].community_scan,
        args[0].model_version,
    )

import argparse
import os
import sys
import uuid
from pathlib import Path
from typing import Dict

from hiddenlayer import HiddenlayerServiceClient
from hiddenlayer.sdk.rest.models import ScanResultsV2
from urllib.parse import urlparse

import markdown


def main(model_path: str, api_url: str = "https://api.hiddenlayer.ai"):
    """
    Scans a model using the HiddenLayer API.

    Currently supported scan locations are files on disk or s3.
    """
    hl_api_id = os.getenv("HL_CLIENT_ID")
    hl_api_key = os.getenv("HL_CLIENT_SECRET")

    hl_client = HiddenlayerServiceClient(
        host=api_url, api_id=hl_api_id, api_key=hl_api_key
    )

    markdown_generator = markdown.MarkdownStringGenerator()
    markdown_generator.h2("Model Scanner Results")
    markdown_generator.create_table(["File Name", "Result"])

    results: Dict[str | Path, ScanResultsV2] = {}

    if model_path.startswith("s3://"):
        bucket, key = model_path.split("/", 2)[-1].split("/", 1)
        file = key.split("/")[-1]

        scan_results = hl_client.model_scanner.scan_s3_model(
            model_name=file, bucket=bucket, key=key
        )

        results[model_path] = scan_results
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

        results[model_path] = scan_results
    else:
        model_path: Path = Path(model_path)

        files = list(model_path.rglob("*")) if model_path.is_dir() else [model_path]

        for file in files:
            if Path(file).is_dir():
                continue

            scan_results = hl_client.model_scanner.scan_file(
                model_name=file.name, model_path=file
            )
            results[file] = scan_results

    detected = False  # Whether we detected a malicious file during the scans

    for path, scan_result in results.items():
        if scan_result.detections:
            detected = True
            markdown_generator.add_table_row([str(path), ":x:"])
        else:
            markdown_generator.add_table_row([str(path), ":white_check_mark:"])

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

    if detected:
        print("Malicious models found!")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Model Scanner")
    parser.add_argument("model_path", type=str)
    parser.add_argument("api_url", type=str)
    parser.add_argument("azure_sas_key", type=str, required=False)
    args = parser.parse_args()

    main(args.model_path, args.api_url)

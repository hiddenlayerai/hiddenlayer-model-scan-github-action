# HiddenLayer Model Scanner Github Action

Integrate model scanning into your continuous integration (CI) process with HiddenLayer's GitHub Actions (GHA) integration. This action can scan your models that are stored in a repository or on Amazon S3.

By default, the results are stored in the GitHub Actions Job Summary. You can write the results to a GitHub Pull Request (see example below).

The model scan results can display the following:

- Green checkmark: No issues identified in the model.
- Red X: Issues were identified in the model. See the scan results for more information.

![image](https://github.com/hiddenlayerai/hiddenlayer-model-scan-github-action/assets/9558507/dbebe8db-7e68-479d-a244-070238adf00d)

For more information about GitHub Actions:

- Read the [Understanding GitHub Actions](https://docs.github.com/en/actions/learn-github-actions/understanding-github-actions) page.
- Read the [GitHub Actions Quickstart](https://docs.github.com/en/actions/quickstart) for a quick overview.

## Inputs

`model_path` (required): Path to the model(s), can either be a path to a single model in the repo, a folder containing the model(s) in the repo or a path on s3 to the model.

`api_url`: URL to the HiddenLayer API if you're using the OEM/self hosted version. Defaults to `https://api.hiddenlayer.ai`.

> Note: For customers using the Enterprise Self Hosted Model Scanner, please ensure your Github Action runners can make network requests to the Model Scanner API.

## Environment Variables

`HL_CLIENT_ID` (**required for SaaS only**): Your HiddenLayer API Client ID.

`HL_CLIENT_SECRET` (**required for SaaS only**): Your HiddenLayer API Client Secret.

`AWS_ACCESS_KEY_ID`: Required when scanning a model on S3 if not using self hosted runners with access to S3.

`AWS_SECRET_ACCESS_KEY`: Required when scanning a model on S3 if not using self hosted runners with access to S3.

`AZURE_BLOB_SAS_KEY`: Required when scanning a model file in a Azure Blob private container.

## Output

`detection_results`: A Markdown table with detection results that can be posted to PRs and Issues.

## Example Usage

### Scanning a model using the SaaS Platform

```yaml
jobs:
  scan_model:
    runs-on: ubuntu-latest
    name: Scan a model
    steps:
      - uses: actions/checkout@v3
      - name: Scan model
        id: scan_model
        uses: hiddenlayerai/hiddenlayer-model-scan-github-action@v0.2.0
        with:
          model_path: ./models/pytorch_model.bin
        env:
          HL_CLIENT_ID: ${{ secrets.HL_CLIENT_ID }}
          HL_CLIENT_SECRET: ${{ secrets.HL_CLIENT_SECRET }}
```

### Scanning a model using the Enterprise Self Hosted Model Scanner

```yaml
jobs:
  scan_model:
    runs-on: ubuntu-latest
    name: Scan a model
    steps:
      - uses: actions/checkout@v3
      - name: Scan model
        id: scan_model
        uses: hiddenlayerai/hiddenlayer-model-scan-github-action@latest
        with:
          model_path: ./models/pytorch_model.bin
          api_url: "https://your.enterprise.url"
```

### Scanning a model folder

```yaml
jobs:
  scan_model_folder:
    runs-on: ubuntu-latest
    name: Scan a local model folder
    steps:
      - uses: actions/checkout@v3
      - name: Scan model folder
        id: scan_model_folder
        uses: hiddenlayerai/hiddenlayer-model-scan-github-action@v0.2.0
        with:
          model_path: ./models
        env:
          HL_CLIENT_ID: ${{ secrets.HL_CLIENT_ID }}
          HL_CLIENT_SECRET: ${{ secrets.HL_CLIENT_SECRET }}
```

### Scanning a model on S3

```yaml
jobs:
  scan_model_s3:
    runs-on: ubuntu-latest
    name: Scan a model on s3
    steps:
      - uses: actions/checkout@v3
      - name: Scan model on s3
        id: scan_model_s3
        uses: hiddenlayerai/hiddenlayer-model-scan-github-action@v0.2.0
        with:
          model_path: s3://bucket/pytorch_model.bin
        env:
          HL_CLIENT_ID: ${{ secrets.HL_CLIENT_ID }}
          HL_CLIENT_SECRET: ${{ secrets.HL_CLIENT_SECRET }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

### Scanning a model on Azure Blob Storage

```yaml
jobs:
  scan_model_azure_blob:
    runs-on: ubuntu-latest
    name: Scan a model on Azure Blob
    steps:
      - uses: actions/checkout@v3
      - name: Scan model on Azure Blob
        id: scan_model_azure
        uses: hiddenlayerai/hiddenlayer-model-scan-github-action@v0.2.0
        with:
          model_path: https://<storageaccountname>.blob.core.windows.net/<container>/path/to/model.bin
        env:
          HL_CLIENT_ID: ${{ secrets.HL_CLIENT_ID }}
          HL_CLIENT_SECRET: ${{ secrets.HL_CLIENT_SECRET }}
          AZURE_BLOB_SAS_KEY: ${{ secrets.SAS_KEY }}
```

### Post Scan Results to a PR

```yaml
jobs:     
  scan_model_folder:
    runs-on: ubuntu-latest
    name: Scan models
    steps:
      - uses: actions/checkout@v3
      - name: Scan model folder
        id: scan_model_folder
        uses: hiddenlayerai/hiddenlayer-model-scan-github-action@v0.2.0
        with:
          model_path: ./path_to_model_folder or s3 path
        env:
          HL_CLIENT_ID: ${{ secrets.HL_CLIENT_ID }}
          HL_CLIENT_SECRET: ${{ secrets.HL_CLIENT_SECRET }}
      - name: Post Results
        id: post_results
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '${{ steps.scan_model_folder.outputs.detection_results }}'
            })
```

# HiddenLayer Model Scanner Github Action

This action scans models stored in the repo or on S3. Results by default are stored in the Github Action Job Summary, with the ability to write the results to a Pull Request.

![image](https://github.com/hiddenlayerai/hiddenlayer-model-scan-github-action/assets/9558507/dbebe8db-7e68-479d-a244-070238adf00d)

## Inputs

`model_path` (required): Path to the model(s), can either be a path to a single model in the repo, a folder containing the model(s) in the repo or a path on s3 to the model.

`api_url`: URL to the HiddenLayer API if you're using the OEM/self hosted version. Defaults to `https://api.hiddenlayer.ai`.

## Environment Variables

`HL_CLIENT_ID` (required): Your HiddenLayer API Client ID.

`HL_CLIENT_SECRET` (required): Your HiddenLayer API Client Secret.

`AWS_ACCESS_KEY_ID`: Required when scanning a model on S3 if not using self hosted runners with access to S3.

`AWS_SECRET_ACCESS_KEY`: Required when scanning a model on S3 if not using self hosted runners with access to S3.

## Output

`detection_results`: A Markdown table with detection results that can be posted to PRs and Issues.

## Example Usage

### Scanning a model

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
        env:
          HL_CLIENT_ID: ${{ secrets.HL_CLIENT_ID }}
          HL_CLIENT_SECRET: ${{ secrets.HL_CLIENT_SECRET }}
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
        uses: hiddenlayerai/hiddenlayer-model-scan-github-action@latest
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
        id: scan_model_folder
        uses: hiddenlayerai/hiddenlayer-model-scan-github-action@latest
        with:
          model_path: s3://bucket/pytorch_model.bin
        env:
          HL_CLIENT_ID: ${{ secrets.HL_CLIENT_ID }}
          HL_CLIENT_SECRET: ${{ secrets.HL_CLIENT_SECRET }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
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
        uses: hiddenlayerai/hiddenlayer-model-scan-github-action@latest
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

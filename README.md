# Infrastructure as Code Security Scanner with AI Remediation

A terminal-only Python CLI that scans Terraform with [Trivy](https://trivy.dev/), parses its JSON findings, and asks an ILMU-hosted language model for plain-English explanations, practical impact, and reviewable Terraform remediation examples. Trivy remains the source of truth for detection; AI is used only as an explanation layer.

The scanner sends findings to ILMU in batches of 10 to reduce API calls. It never generates report files.

## Safety warning

[TerraGoat](https://github.com/bridgecrewio/terragoat) is intentionally vulnerable. This project only performs static analysis of its files. Do not run `terraform init`, `terraform plan`, or `terraform apply` against TerraGoat, and never deploy it to a real cloud account.

AI-generated remediation is a starting point for human review. Validate provider versions, resource references, organisational requirements, and the result of a fresh Trivy scan before using a suggestion.

## Workflow

```text
Terraform file or directory
          |
          v
Trivy performs deterministic checks
          |
          v
Python parses and flattens JSON findings
          |
          v
Findings are sent to ILMU in batches of 10
          |
          v
Responses are matched by stable finding keys
          |
          v
Rich prints a report grouped by severity
```

## Requirements

- Python 3.11 or newer
- Trivy available on `PATH` (tested with 0.73.0)
- An ILMU API key with access to the intended model

Install Trivy using the [official installation instructions](https://trivy.dev/docs/latest/getting-started/installation/). On Windows, download the Windows 64-bit release archive, extract `trivy.exe`, and add its directory to your user `PATH`.

Verify the tools:

```powershell
python --version
trivy --version
```

## Set up the project

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the pinned Python dependencies:

```powershell
python -m pip install -r requirements.txt
```

Clone the vulnerable fixture into the ignored fixture directory:

```powershell
git clone https://github.com/bridgecrewio/terragoat.git fixtures/terragoat
```

## Configure ILMU

Do not put the API key in `scanner.py`, `README.md`, `.env`, a command-line argument, or Git history. Set it as an environment variable in the PowerShell session where you run the scanner:

```powershell
$env:ILMU_API_KEY = "<your sk-prefixed key>"
```

This value lasts only for the current PowerShell process. Closing the terminal removes it from that session.

The ILMU console displays the product name “ILMU GLM-5.1,” but the public documentation does not confirm its exact API model ID. Discover the IDs available to your account without making a completion request:

```powershell
python scanner.py --list-models
```

Find the ID that corresponds to GLM-5.1 in your ILMU console, then set it exactly as returned:

```powershell
$env:ILMU_MODEL = "exact-model-id-from-the-list"
```

Never guess the model ID. `ILMU_API_KEY` is the secret credential; `ILMU_MODEL` is a non-secret identifier.

To remove the values from the current PowerShell session manually:

```powershell
Remove-Item Env:ILMU_API_KEY
Remove-Item Env:ILMU_MODEL
```

## Usage

First test the deterministic scan without spending ILMU tokens:

```powershell
python scanner.py --no-ai fixtures/terragoat/terraform/aws/s3.tf
```

Scan the same file with ILMU explanations:

```powershell
python scanner.py fixtures/terragoat/terraform/aws/s3.tf
```

Scan the TerraGoat AWS directory:

```powershell
python scanner.py fixtures/terragoat/terraform/aws
```

Scan another Terraform file or directory:

```powershell
python scanner.py path/to/terraform
```

Display command help:

```powershell
python scanner.py --help
```

## Behaviour and failure handling

- Trivy JSON is captured from standard output in memory; no report is written.
- Trivy diagnostics remain separate on standard error.
- Only failed entries in Trivy's `Misconfigurations` arrays become report findings.
- Findings are sorted into `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `UNKNOWN` sections.
- Each ILMU request contains at most 10 findings.
- Each batch has a 5,000-token output ceiling to bound accidental over-generation.
- Responses are matched using keys such as `finding-1`, not assumed array positions.
- If an ILMU batch fails or returns malformed data, the scanner stops further AI requests to avoid wasting tokens and still prints the remaining Trivy results.
- `--no-ai` requires neither `ILMU_API_KEY` nor `ILMU_MODEL`.

## Project structure

```text
.
|-- scanner.py          # Complete CLI implementation
|-- requirements.txt    # Direct Python dependencies
|-- STUDY_GUIDE.md      # Architecture and concept guide
|-- fixtures/
|   `-- terragoat/      # Local vulnerable fixture (ignored by Git)
|-- .gitignore
`-- README.md
```

## Limitations

- AI output is probabilistic and may contain unsuitable Terraform syntax.
- The program validates the response shape and finding keys, but it does not compile or apply remediation snippets.
- It does not deduplicate similar Trivy findings because each affected resource is useful evidence.
- It scans Terraform configuration, not deployed cloud state.
- It uses ILMU's OpenAI-compatible Chat Completions endpoint and depends on the selected model supporting that endpoint.

For a detailed explanation of the architecture, code, security decisions, and suggested learning exercises, read [STUDY_GUIDE.md](STUDY_GUIDE.md).

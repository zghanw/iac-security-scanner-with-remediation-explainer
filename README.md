# Infrastructure as Code Security Scanner with AI Remediation
This project is a command-line tool for reviewing Terraform configurations. It will use [Trivy](https://trivy.dev/) for deterministic security checks, then send each finding to ILMU GLM-5.1 for a plain-English explanation, practical risk summary, and suggested Terraform remediation. The final results will be displayed as a readable terminal report.


## Planned workflow

```text
Terraform files
      |
      v
Trivy applies deterministic security rules
      |
      v
Python extracts structured findings
      |
      v
Findings are divided into batches
      |
      v
ILMU GLM-5.1 explains risks and proposes remediations
      |
      v
Python matches each response to its finding
      |
      v
Terminal report is grouped by severity
```

Trivy remains the source of truth for detection. The language model is planned as an explanation and remediation layer, not as a replacement security scanner.

## Project structure

```text
.
|-- scanner.py          # Scanner entry point (implementation pending)
|-- requirements.txt    # Pinned Python dependencies
|-- fixtures/
|   `-- terragoat/      # Local vulnerable Terraform fixture (git-ignored)
|-- .gitignore
`-- README.md
```

## Prerequisites

- Python 3
- Trivy installed and available on your `PATH`
- Credentials and an API endpoint for ILMU GLM-5.1

Verify the local tools with:

```bash
python --version
trivy --version
```

## Set up the Python environment

Create and activate a virtual environment:

```bash
python -m venv .venv
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

On macOS or Linux:

```bash
source .venv/bin/activate
```

Install the pinned dependencies:

```bash
python -m pip install -r requirements.txt
```

The current dependencies are:

- `openai==2.53.0` for the planned OpenAI-compatible ILMU client
- `rich==15.0.0` for the planned terminal report

## Test fixture

The lesson workspace includes [TerraGoat](https://github.com/bridgecrewio/terragoat) under `fixtures/terragoat/`. TerraGoat contains intentionally vulnerable infrastructure definitions that can exercise the scanner during development.

The fixture is excluded from this repository through `.gitignore`, so a fresh clone will not contain it unless you add it locally.

Do not deploy the TerraGoat configurations to a real cloud account. They are intentionally insecure.

## Expected output

Once implemented, each reported finding is intended to include:

- severity and Trivy rule identifier
- affected Terraform file and resource
- plain-English explanation
- practical impact
- suggested remediation snippet

AI-generated remediations must be reviewed before use. They can be incomplete or unsuitable for a specific infrastructure environment.
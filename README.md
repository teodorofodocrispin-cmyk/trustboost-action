# TrustBoost PII Scanner — GitHub Action

Scan your repository files for PII before commits reach production.
Powered by [TrustBoost](https://github.com/teodorofodocrispin-cmyk/TrustBoost-PII-Sanitizer).

## Quick Start

Add this to your `.github/workflows/pii-scan.yml`:

```yaml
name: PII Scan

on: [push, pull_request]

jobs:
  pii-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: TrustBoost PII Scan
        uses: teodorofodocrispin-cmyk/trustboost-action@v1
        with:
          files: "**/*.txt,**/*.md,**/*.json,**/*.csv"
          fail_on_critical: "true"
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `files` | Glob pattern of files to scan | `**/*.txt,**/*.md,**/*.json,**/*.csv` |
| `wallet_address` | Wallet ID for quota tracking | `github-action` |
| `fail_on_critical` | Fail if CRITICAL PII detected | `true` |
| `fail_on_private` | Fail if PRIVATE PII detected | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `pii_found` | Whether PII was found |
| `files_scanned` | Number of files scanned |
| `critical_count` | Files with CRITICAL PII |
| `private_count` | Files with PRIVATE PII |

## Risk Categories

| Category | Examples |
|----------|---------|
| CRITICAL | Private keys, passwords, API keys, seed phrases |
| PRIVATE | Emails, phone numbers, national IDs, addresses |
| SENSITIVE | Usernames, general locations |
| CLEAN | No PII detected |

## Multilingual Support

Detects PII in EN, ES (LATAM), PT (BR/PT), DE, JA — including:
- RFC (Mexico), CUIT (Argentina), CPF/CNPJ (Brazil)
- Personalausweis (Germany), My Number (Japan)

## Free Usage

Uses TrustBoost preview endpoint — no wallet, no payment required for scanning.

For full sanitization with audit trail: [TrustBoost TRIAL](https://github.com/teodorofodocrispin-cmyk/TrustBoost-PII-Sanitizer#trial)

## License

MIT

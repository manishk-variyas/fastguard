# fastguard

FastGuard scans your FastAPI backend for security issues. It looks at your code, checks dependencies against known CVEs, and optionally uses an LLM to spot vulnerabilities static analysis might miss.

## install

```bash
curl -sSL https://raw.githubusercontent.com/manishk-variyas/fastguard/main/install.sh | sh
```

Or if you already have uv:

```bash
uv tool install git+https://github.com/manishk-variyas/fastguard.git
```

## usage

Point it at a FastAPI project:

```bash
fastguard scan ./my-api
```

It will output an HTML report by default. You can change the format:

```bash
fastguard scan ./my-api --output json
fastguard scan ./my-api --output markdown --report results.md
```

Filter by severity if you only care about the bad stuff:

```bash
fastguard scan ./my-api --severity critical,high
```

## what it does

- Walks your project and collects Python files, configs, requirements files
- Runs pattern-based checks for common FastAPI misconfigurations
- Looks up your dependencies in the CVE database
- Runs your code through an AI model (OpenCode) for a second pass
- Generates a report with findings, severity, impact, and suggested fixes

## requirements

Python 3.9 or newer. That's it.

## build from source

```bash
git clone https://github.com/manishk-variyas/fastguard.git
cd fastguard
make install
```

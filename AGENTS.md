# Repository Guidelines

## Project Structure & Module Organization

This repository is a small Python 3.12 NeMo Guardrails HTTP service.

- `main.py` defines the FastAPI/NeMo server setup and public API routes.
- `masking.py` implements deterministic request/response redaction middleware.
- `pii.py` contains the experimental local PII preview detector.
- `masking.yml` contains built-in masking rules.
- `configs/` contains NeMo Guardrails profiles such as `default`, `customer-support`, and `resume-screening`.
- `scripts/test_guardrails.py` contains smoke tests for masking, PII preview, configs, and HTTP endpoints.
- `docs/` contains feature and frontend handoff documentation.

Do not commit real secrets from `.env`.

## Build, Test, and Development Commands

Install or sync dependencies:

```bash
uv sync
```

Run the service locally:

```bash
uv run --env-file .env python main.py
```

Run local smoke tests without OpenAI calls:

```bash
uv run python scripts/test_guardrails.py
```

Run HTTP smoke tests against a running server:

```bash
uv run python scripts/test_guardrails.py --server-url http://localhost:8000
```

Docker development:

```bash
docker compose up --build
```

## Coding Style & Naming Conventions

Use Python type hints, small functions, and explicit validation for API payloads. Keep identifiers in English and use `snake_case` for functions, variables, and module names. YAML rule names should be short, lowercase, and hyphenated, for example `email-address` or `secret-token`.

No formal formatter or linter is configured. Keep formatting consistent with the existing files: 4-space indentation, concise imports, and readable multiline dictionaries.

## Testing Guidelines

Add or update `scripts/test_guardrails.py` for behavior changes. Prefer deterministic tests that do not call OpenAI. Live chat tests are optional and should be run only when token usage is intentional:

```bash
uv run --env-file .env python scripts/test_guardrails.py --server-url http://localhost:8000 --live
```

For new masking behavior, include positive checks for expected placeholders and negative checks for leaked raw values.

## Commit & Pull Request Guidelines

The current git history uses short messages such as `api-v1` and `first`; no strict convention is established. Use concise imperative commit messages, for example `add pii preview endpoint`.

Pull requests should describe the behavior change, list tested commands, and call out any API/schema changes. Include sample requests or responses when changing frontend-facing endpoints.

## Security & Configuration Tips

Keep `.env` local and never include real API keys in docs, tests, or fixtures. Prefer preview endpoints before sending sensitive text to live chat.

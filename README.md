# NeMo Guardrails Microservice

This project runs NeMo Guardrails as a small HTTP service using the built-in FastAPI server.

## Local Run

Your real `.env` should contain:

```bash
OPENAI_API_KEY=...
```

Install dependencies:

```bash
uv sync
```

Start the service:

```bash
uv run --env-file .env python main.py
```

The service listens on `http://localhost:8000`.

For browser frontends, CORS allows `http://localhost:3000` and `http://127.0.0.1:3000` by default. Override it in `.env`:

```bash
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

Check masking rules without calling OpenAI:

```bash
curl http://localhost:8000/v1/masking/rules
```

## Docker Run

```bash
docker compose up --build
```

`docker-compose.yml` loads `OPENAI_API_KEY` from `.env`. The `.dockerignore` file prevents `.env` from being copied into the Docker image.

`.env` and `.venv` are ignored by `.gitignore`; do not commit real API keys.

## Smoke Tests

List loaded guardrails configs:

```bash
curl http://localhost:8000/v1/rails/configs
```

Preview keyword masking without calling OpenAI:

```bash
curl -X POST http://localhost:8000/v1/masking/preview \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Email admin@example.com about internal-project-x and OPENAI_API_KEY sk-test_abcdefghijklmnopqrstuvwxyz"
  }'
```

Send a guarded chat request:

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {
        "role": "user",
        "content": "Say hello in one sentence."
      }
    ],
    "guardrails": {
      "config_id": "default"
    }
  }'
```

Use the customer support guardrail example:

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {
        "role": "user",
        "content": "What is your return policy?"
      }
    ],
    "guardrails": {
      "config_id": "customer-support"
    }
  }'
```

Use the resume screening guardrail example:

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {
        "role": "user",
        "content": "I am hiring the founding AI engineer. Rank these candidates based on job-relevant skills only.\n\n1. Software Engineer\nName: 陳子豪\nEmail: zihao.chen@email.com\nPhone: 0912-345-678\nAge: 26\nGender: Male\nSummary: Full-stack engineer specializing in AI Agents, RAG, FastAPI, Docker, Kubernetes, and production AI apps."
      }
    ],
    "guardrails": {
      "config_id": "resume-screening"
    }
  }'
```

## Configuration

Guardrails configs are in `configs/`.

- `config.yml` defines the OpenAI model and enables input/output rails.
- `prompts.yml` defines the policy used by the self-check rails.
- `masking.yml` defines deterministic keyword and regex masking rules.

Additional examples are in `docs/guardrail-examples.md`.

## Keyword Masking

The service masks configured keywords and regex patterns on:

- incoming `/v1/chat/completions` requests before they reach NeMo Guardrails or OpenAI
- outgoing `/v1/chat/completions` responses before they return to the client
- `/v1/checks` requests and responses

Built-in rules currently cover:

- resume-style `名字` / `姓名` / `Name` fields are removed
- resume-style `Email` / `E-mail` / `電子郵件` / `信箱` fields are removed
- resume-style `電話` / `手機` / `Phone` / `Mobile` / `Tel` fields are removed
- resume-style `年紀` / `年齡` / `Age` fields are removed
- resume-style `性別` / `Gender` / `Sex` fields are removed
- common secrets such as OpenAI keys, AWS keys, GitHub tokens, JWTs, bearer tokens, credit cards, and database URLs

Edit `masking.yml` to add project rules:

```yaml
rules:
  - name: internal-code-name
    type: literal
    pattern: secret-product-name
    replacement: "[PROJECT]"
    case_sensitive: false
```

You can also add temporary comma-separated keywords in `.env`:

```bash
MASK_KEYWORDS=secret-product-name,customer-token
MASK_REPLACEMENT=[REDACTED]
```

## Policy Redaction API

Create named policies for user-managed literal keyword redaction. Policies are stored in SQLite at `data/policies.sqlite3` by default.

Create a policy:

```bash
curl -X POST http://localhost:8000/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "id": "resume-client-a",
    "name": "Resume Client A",
    "enabled": true,
    "replacement": "[REDACTED]",
    "case_sensitive": false,
    "keywords": ["秘密專案", "內部代號A", "client-name"]
  }'
```

Preview a policy without calling OpenAI:

```bash
curl -X POST http://localhost:8000/v1/policies/resume-client-a/preview \
  -H "Content-Type: application/json" \
  -d '{"text": "秘密專案 belongs to client-name and admin@example.com"}'
```

Apply a policy to chat by adding `guardrails.policy_id`. The policy keywords are combined with the built-in `masking.yml` rules:

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {
        "role": "user",
        "content": "Summarize this resume mentioning 秘密專案."
      }
    ],
    "guardrails": {
      "config_id": "resume-screening",
      "policy_id": "resume-client-a"
    }
  }'
```

## Tests

Run local masking and config tests without calling OpenAI:

```bash
uv run python scripts/test_guardrails.py
```

If the service is running, include an HTTP masking preview smoke test:

```bash
uv run python scripts/test_guardrails.py --server-url http://localhost:8000
```

Live chat tests call `/v1/chat/completions` and consume OpenAI tokens:

```bash
uv run --env-file .env python scripts/test_guardrails.py --server-url http://localhost:8000 --live
```
# nemo-guardrail

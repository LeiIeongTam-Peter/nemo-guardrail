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

For browser frontends, CORS allows `http://localhost:3000`–`3002` and `http://127.0.0.1:3000`–`3002` by default. Override it in `.env`:

```bash
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001,http://localhost:3002,http://127.0.0.1:3002
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

Preview deterministic masking without calling OpenAI:

```bash
curl -X POST http://localhost:8000/v1/masking/preview \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Email admin@example.com with OPENAI_API_KEY sk-test_abcdefghijklmnopqrstuvwxyz and AKIAIOSFODNN7EXAMPLE"
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
- `masking.yml` defines deterministic literal and regex masking rules.

Additional examples are in `docs/guardrail-examples.md`.

## Deterministic Redaction

The service masks configured literal and regex patterns on:

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

Edit `masking.yml` to add deployment-wide rules:

```yaml
rules:
  - name: internal-token-format
    type: regex
    pattern: "\\bcorp_[A-Za-z0-9]{24}\\b"
    replacement: "[INTERNAL_TOKEN]"
    case_sensitive: false
```

Avoid using this as a per-user keyword policy system in production. Exact business keywords only work when you already know the keyword before the user sends traffic, so they do not scale well for self-serve users.

You can still add temporary deployment-level emergency keywords in `.env`:

```bash
MASK_KEYWORDS=secret-product-name,customer-token
MASK_REPLACEMENT=[REDACTED]
```

## Optional Chat PII Redaction

Enable PII masking for a chat call by adding `guardrails.enable_pii: true`. This runs after deterministic masking and before the request reaches NeMo/OpenAI.

Supported providers:

- `nemo`: NeMo GLiNER-PII through NVIDIA hosted NIM or a local compatible endpoint.
- `openai-guardrails`: OpenAI Guardrails `Contains PII`, running locally through Microsoft Presidio and spaCy. This does not call the OpenAI API.

NeMo chat example:

```json
{
  "guardrails": {
    "config_id": "resume-screening",
    "enable_pii": true,
    "pii_provider": "nemo",
    "pii_score_threshold": 0.5,
    "pii_entities": ["first_name", "last_name", "email", "phone_number"]
  }
}
```

OpenAI Guardrails chat example:

```json
{
  "guardrails": {
    "config_id": "resume-screening",
    "enable_pii": true,
    "pii_provider": "openai-guardrails",
    "pii_entities": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"]
  }
}
```

Use `PII_PROVIDER=openai-guardrails` in `.env` to make OpenAI Guardrails the default PII provider when a request does not specify one.

## Experimental PII Preview

The service exposes an experimental PII detector endpoint with selectable providers.

For NeMo, the default hosted endpoint calls NVIDIA's GLiNER-PII NIM endpoint and requires `NVIDIA_API_KEY` or `NEMO_PII_API_KEY`. To use a local NIM or compatible GLiNER server, set `NEMO_PII_SERVER_ENDPOINT`.

```bash
export NVIDIA_API_KEY=nvapi-your-nvidia-api-key
# Optional local endpoint override:
# export NEMO_PII_SERVER_ENDPOINT=http://localhost:8001/v1/chat/completions
```

```bash
curl -X POST http://localhost:8000/v1/pii/preview \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "nemo",
    "text": "My name is Peter, my email is peter@example.com, phone is 416-555-0199."
  }'
```

For OpenAI Guardrails PII, no OpenAI API key is required. It runs locally through the `openai-guardrails` package using Presidio/spaCy:

```bash
curl -X POST http://localhost:8000/v1/pii/preview \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai-guardrails",
    "text": "My name is Peter, my email is peter@example.com, phone is 416-555-0199.",
    "entities": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"]
  }'
```

The first OpenAI Guardrails PII run needs the `en_core_web_sm` spaCy model. Docker installs it during image build. For local development, run this once if the provider asks for it:

```bash
uv run python -m spacy download en_core_web_sm
```

Example response:

```json
{
  "enabled": true,
  "provider": "nemo",
  "engine": "nemo-gliner-pii",
  "model": "nvidia/gliner-pii",
  "language": "en",
  "score_threshold": 0.5,
  "masked": "My name is [FIRST_NAME], my email is [EMAIL], phone is [PHONE_NUMBER].",
  "entities": [
    {
      "type": "first_name",
      "start": 11,
      "end": 16,
      "score": 0.99,
      "text": "Peter",
      "replacement": "[FIRST_NAME]"
    }
  ]
}
```

Use this endpoint to compare NeMo GLiNER-PII detection against deterministic `masking.yml` redaction.

## Combined Redaction Preview

Use `/v1/redaction/preview` to test both layers together without calling OpenAI:

1. deterministic `masking.yml` rules
2. optional PII masking on the deterministic result

```bash
curl -X POST http://localhost:8000/v1/redaction/preview \
  -H "Content-Type: application/json" \
  -d '{
    "text": "王小明 can be reached at peter@example.com.",
    "enable_pii": true,
    "provider": "openai-guardrails",
    "entities": ["PERSON", "EMAIL_ADDRESS"],
    "score_threshold": 0.5
  }'
```

Set `"enable_pii": false` to test only the deterministic regex/literal layer. This is useful when provider credentials or local PII dependencies are not available.

## Tests

Run local masking and config tests without calling OpenAI:

```bash
uv run python scripts/test_guardrails.py
```

Run the live NeMo GLiNER-PII preview test:

```bash
uv run --env-file .env python scripts/test_guardrails.py --nemo-pii
```

Run the local OpenAI Guardrails PII preview test:

```bash
uv run python scripts/test_guardrails.py --openai-pii
```

If the service is running, include an HTTP masking preview smoke test:

```bash
uv run python scripts/test_guardrails.py --server-url http://localhost:8000
```

Include the HTTP NeMo PII smoke test:

```bash
uv run --env-file .env python scripts/test_guardrails.py --server-url http://localhost:8000 --nemo-pii
```

Include the HTTP OpenAI Guardrails PII smoke test:

```bash
uv run python scripts/test_guardrails.py --server-url http://localhost:8000 --openai-pii
```

Live chat tests call `/v1/chat/completions` and consume OpenAI tokens:

```bash
uv run --env-file .env python scripts/test_guardrails.py --server-url http://localhost:8000 --live
```

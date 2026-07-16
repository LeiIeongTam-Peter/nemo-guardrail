# Guardrail Feature Examples

This project currently loads multiple guardrails configurations from `configs/`.

## Multiple Configs

Use `guardrails.config_id` to choose a config per request.

```json
{
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
}
```

## Topic Control

`configs/customer-support` shows topic control using `self_check_input`.
The policy allows order, return, refund, shipping, product, account, and store policy questions.
Unrelated questions should be blocked or redirected.

## Resume Screening

`configs/resume-screening` is tuned for candidate ranking and interview recommendations.
It allows resume screening only when the assistant evaluates job-relevant skills, experience, impact, and role fit.
For this workflow, protected and private resume fields are removed by deterministic preprocessing before the request reaches the LLM, and output masking removes leaked names or contact details from responses.
This avoids false positives from generic self-check rails in hiring/ranking prompts.

Use it with:

```json
{
  "guardrails": {
    "config_id": "resume-screening"
  }
}
```

## Deterministic Redaction

`masking.yml` defines deterministic literal and regex masking rules.
This runs before and after the NeMo Guardrails API call, so sensitive text is masked in both directions.

Preview masking without calling OpenAI:

```bash
curl -X POST http://localhost:8000/v1/masking/preview \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Email admin@example.com with OPENAI_API_KEY sk-test_abcdefghijklmnopqrstuvwxyz and AKIAIOSFODNN7EXAMPLE"
  }'
```

Example output:

```json
{
  "enabled": true,
  "masked": {
    "text": "Email [EMAIL] with [SECRET_NAME] [OPENAI_API_KEY] and [AWS_ACCESS_KEY_ID]"
  }
}
```

Resume-style Chinese and English PII fields are removed before the request reaches the LLM:

```text
名字：陳子豪 -> removed
Email：zihao.chen@email.com -> removed
電話：0912-345-678 -> removed
年紀：26 歲 -> removed
性別：男 -> removed
Name: Peter Tam -> removed
Age: 28 years old -> removed
Gender: female -> removed
```

## NeMo PII

`/v1/pii/preview` and `/v1/redaction/preview` run NeMo PII detection after deterministic masking.

NeMo GLiNER-PII uses NVIDIA hosted NIM or a local compatible endpoint:

```bash
curl -X POST http://localhost:8000/v1/pii/preview \
  -H "Content-Type: application/json" \
  -d '{
    "text": "My name is Peter, my email is peter@example.com, phone is 416-555-0199."
  }'
```

In chat, enable PII under `guardrails`:

```json
{
  "guardrails": {
    "config_id": "default",
    "enable_pii": true
  }
}
```

## Dialog Flow

For strict workflows, add Colang flows under a `rails/` directory.
Example use cases:

- require order number before checking order status
- ask for missing fields before creating a support ticket
- force escalation when the user reports fraud or account takeover

## RAG And Retrieval Rails

For RAG, add a retrieval layer in the application and use retrieval rails to validate retrieved chunks before they are passed to the LLM.
Example use cases:

- remove chunks containing internal-only notes
- block low-confidence retrieved context
- detect sensitive data in retrieved documents

## Custom Actions

Custom actions let guardrails call Python logic or external APIs.

Example file shape:

```text
configs/customer-support/
  actions.py
  config.yml
  prompts.yml
```

Example action:

```python
from nemoguardrails.actions import action


@action()
async def lookup_order_status(order_id: str):
    return {
        "order_id": order_id,
        "status": "in_transit",
        "eta": "2 business days",
    }
```

## Multiple Models

You can split model duties, for example:

```yaml
models:
  - type: main
    engine: openai
    model: gpt-4o-mini
  - type: self_check_input
    engine: openai
    model: gpt-4o-mini
```

In production, the main model can be stronger while guardrail checks use cheaper or specialized models.

## Deployment

Local:

```bash
uv run --env-file .env python main.py
```

Docker:

```bash
docker compose up --build
```

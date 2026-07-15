# Frontend Handoff: Redaction API

This service is a NeMo Guardrails HTTP microservice. It provides an OpenAI-compatible chat API and applies deterministic redaction before requests reach NeMo/OpenAI and before responses return to the client.

## Change Summary

The backend removed the previous user-managed keyword policy feature. The frontend should no longer expose policy CRUD, policy selection, or policy preview flows.

Removed backend surface:

- `POST /v1/policies`
- `GET /v1/policies`
- `GET /v1/policies/{policy_id}`
- `PUT /v1/policies/{policy_id}`
- `DELETE /v1/policies/{policy_id}`
- `POST /v1/policies/{policy_id}/preview`
- `POST /v1/policies/{policy_id}/debug-chat-request`
- `guardrails.policy_id` on `/v1/chat/completions`
- `policy_id` on `/v1/redaction/preview`

Replacement backend surface:

- `/v1/masking/rules` for deterministic rule visibility
- `/v1/masking/preview` for fast deterministic redaction preview
- `/v1/pii/preview` for direct PII provider testing
- `/v1/redaction/preview` for deterministic plus optional PII preview
- `/v1/chat/completions` with `guardrails.config_id` and optional `guardrails.enable_pii`

The production redaction model is:

- built-in deterministic rules from `masking.yml`
- optional PII provider redaction with `guardrails.enable_pii`
- no user-managed keyword policy API

## Frontend Scope

Recommended frontend screens:

1. Config selector for `guardrails.config_id`.
2. Masking preview using `/v1/masking/preview`.
3. PII preview using `/v1/pii/preview`.
4. Combined redaction preview using `/v1/redaction/preview`.
5. Chat tester using `/v1/chat/completions`.

Do not build create/edit/delete policy screens. `/v1/policies/*` and `guardrails.policy_id` are removed.

## Migration Checklist

Remove these frontend features:

- policy list page
- policy editor form
- keyword tag input or keyword textarea
- policy enable/disable toggle
- policy replacement and case sensitivity controls
- policy preview panel backed by `/v1/policies/{policy_id}/preview`
- debug chat request panel backed by `/v1/policies/{policy_id}/debug-chat-request`
- `policy_id` field from any redaction preview request
- `guardrails.policy_id` field from any chat request

Keep or add these frontend features:

- config selector for `default`, `customer-support`, and `resume-screening`
- deterministic preview text area using `/v1/masking/preview`
- combined preview text area using `/v1/redaction/preview`
- optional PII toggle mapped to `enable_pii` for preview and `guardrails.enable_pii` for chat
- PII provider selector mapped to `provider` for preview and `guardrails.pii_provider` for chat
- optional encoded PII toggle mapped to `detect_encoded_pii` for preview and `guardrails.pii_detect_encoded` for chat
- optional PII entity multi-select mapped to `entities` for preview and `guardrails.pii_entities` for chat
- clear error state for missing or invalid PII provider credentials

## Behavioral Notes

Exact keyword lists are no longer treated as a production user workflow. They only work when the operator already knows the sensitive term before the user sends traffic, which does not scale for self-serve users.

The frontend should explain redaction as:

1. Deterministic masking catches known classes and configured deployment-wide patterns.
2. Optional PII detection catches supported PII entities using the selected provider.
3. Guardrails configs control conversational policy, topic boundaries, and self-check behavior.

Do not describe PII entities as exact business keywords. They are detector labels such as `email`, `phone_number`, or `first_name`.

Combined redaction always runs deterministic masking first, then the selected PII provider. For example, if `masking.yml` already turns an email address into `[EMAIL]`, the PII provider receives `[EMAIL]` instead of the raw email value.

`/v1/redaction/preview` defaults `enable_pii` to `true`. Chat only runs PII detection when the request explicitly includes `guardrails.enable_pii: true`.

## PII Providers

Supported provider values:

```ts
type PiiProvider = "nemo" | "openai-guardrails";
```

Provider behavior:

- `nemo`: NeMo GLiNER-PII through NVIDIA hosted NIM or a local compatible endpoint. Hosted usage requires `NVIDIA_API_KEY` or `NEMO_PII_API_KEY`.
- `openai-guardrails`: OpenAI Guardrails `Contains PII`, running locally through Microsoft Presidio and spaCy. It does not call the OpenAI API and does not need `OPENAI_API_KEY`.

Default provider is `nemo` unless the backend is started with `PII_PROVIDER=openai-guardrails`.

Suggested provider labels:

- NeMo GLiNER-PII
- OpenAI Guardrails PII

Entity names are provider-specific. NeMo accepts labels such as `first_name`, `email`, and `phone_number`. OpenAI Guardrails accepts labels such as `PERSON`, `EMAIL_ADDRESS`, and `PHONE_NUMBER`; the backend also maps common aliases like `email`, `phone_number`, `first_name`, and `last_name`.

Suggested entity presets:

```ts
const nemoEntityPreset = ["first_name", "last_name", "email", "phone_number"];
const openaiEntityPreset = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"];
```

## Provider Field Mapping

Preview endpoints use top-level PII fields:

```ts
type PreviewPiiFields = {
  provider?: PiiProvider;
  language?: "en";
  score_threshold?: number;
  entities?: string[];
  detect_encoded_pii?: boolean;
};
```

Chat uses the same options under `guardrails` with a `pii_` prefix:

```ts
type ChatGuardrailsFields = {
  config_id?: string;
  enable_pii?: boolean;
  pii_provider?: PiiProvider;
  pii_language?: "en";
  pii_score_threshold?: number;
  pii_entities?: string[];
  pii_detect_encoded?: boolean;
};
```

Backend-only PII fields are removed before the chat request is forwarded to NeMo/OpenAI.

## Endpoints

### List Deterministic Rules

```http
GET /v1/masking/rules
```

Response:

```ts
type MaskingRulesResponse = {
  enabled: boolean;
  rules: string[];
  path_prefixes: string[];
};
```

### Preview Deterministic Masking

```http
POST /v1/masking/preview
Content-Type: application/json
```

Request can be any JSON object. All string values are passed through `masking.yml`.

```json
{
  "text": "Email admin@example.com with AKIAIOSFODNN7EXAMPLE"
}
```

Response:

```ts
type MaskingPreviewResponse = {
  enabled: boolean;
  masked: unknown;
};
```

### Preview PII Detection

```http
POST /v1/pii/preview
Content-Type: application/json
```

```ts
type PiiPreviewRequest = {
  text: string;
  provider?: "nemo" | "openai-guardrails";
  language?: "en";
  score_threshold?: number;
  entities?: string[];
  detect_encoded_pii?: boolean;
};
```

NeMo request:

```json
{
  "provider": "nemo",
  "text": "My name is Peter, my email is peter@example.com.",
  "entities": ["first_name", "email"]
}
```

OpenAI Guardrails request:

```json
{
  "provider": "openai-guardrails",
  "text": "My name is Peter, my email is peter@example.com.",
  "entities": ["PERSON", "EMAIL_ADDRESS"]
}
```

OpenAI Guardrails can optionally check encoded PII:

```json
{
  "provider": "openai-guardrails",
  "text": "Encoded email: cGV0ZXJAZXhhbXBsZS5jb20=",
  "entities": ["EMAIL_ADDRESS"],
  "detect_encoded_pii": true
}
```

Response:

```ts
type PiiEntity = {
  type: string;
  start: number;
  end: number;
  score: number;
  text: string;
  replacement: string;
};

type PiiPreviewResponse = {
  enabled: true;
  provider: PiiProvider;
  engine: string;
  model: string;
  language: "en";
  score_threshold: number;
  detect_encoded_pii: boolean;
  masked: string;
  entities: PiiEntity[];
  supported_entities: string[];
} & (
  | {
      provider: "nemo";
      server_endpoint: string;
      tagged_text: string;
    }
  | {
      provider: "openai-guardrails";
      detected_entities: Record<string, string[]>;
      pii_detected: boolean;
    }
);
```

If `provider` is omitted, the backend uses `PII_PROVIDER`, defaulting to `nemo`. `language` currently supports only `"en"`. `score_threshold` must be greater than `0` and less than or equal to `1`.

### Preview Combined Redaction

```http
POST /v1/redaction/preview
Content-Type: application/json
```

```ts
type RedactionPreviewRequest = {
  text: string;
  enable_pii?: boolean;
  provider?: "nemo" | "openai-guardrails";
  language?: "en";
  score_threshold?: number;
  entities?: string[];
  detect_encoded_pii?: boolean;
};
```

Example deterministic-only request:

```json
{
  "text": "王小明 can be reached at admin@example.com",
  "enable_pii": false
}
```

Example deterministic plus PII request:

```json
{
  "text": "My name is Peter and my email is peter@example.com.",
  "enable_pii": true,
  "provider": "openai-guardrails",
  "score_threshold": 0.5,
  "entities": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"]
}
```

Response:

```ts
type RedactionPreviewResponse = {
  enabled: true;
  language: string;
  score_threshold: number;
  enable_pii: boolean;
  pii_provider: string | null;
  pii_detect_encoded: boolean;
  stages: string[];
  deterministic: {
    enabled: boolean;
    masked: string;
  };
  pii: unknown | null;
  masked: string;
};
```

`stages` is `["deterministic"]` when PII is disabled and `["deterministic", pii_provider]` when PII is enabled. `pii` is the raw `/v1/pii/preview` response for the deterministic-masked text, or `null` when PII is disabled.

If the request includes `policy_id`, the backend returns `400`:

```json
{
  "detail": "policy_id is no longer supported. Use masking.yml rules or enable_pii."
}
```

### Chat

```http
POST /v1/chat/completions
Content-Type: application/json
```

Use the normal NeMo/OpenAI-compatible request shape. Frontend can choose a guardrails config and optionally enable PII:

```json
{
  "model": "gpt-4o-mini",
  "messages": [
    {
      "role": "user",
      "content": "My email is admin@example.com. Summarize this safely."
    }
  ],
  "guardrails": {
    "config_id": "default",
    "enable_pii": true,
    "pii_provider": "openai-guardrails",
    "pii_score_threshold": 0.5,
    "pii_entities": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"],
    "pii_detect_encoded": false
  }
}
```

Backend-only PII fields are removed before forwarding the request. If `guardrails.policy_id` is present, the backend returns `400`:

```json
{
  "detail": "guardrails.policy_id is no longer supported. Use masking.yml rules or guardrails.enable_pii."
}
```

Frontend should send no `policy_id` key at all, not `null`, not an empty string, and not a stale selected policy id.

## Frontend Notes

- Use `/v1/masking/preview` for fast local deterministic checks.
- Use `/v1/redaction/preview` to compare deterministic-only versus deterministic plus PII.
- Switch the entity preset when the selected provider changes.
- Show NeMo credentials status separately from OpenAI Guardrails local dependency status.
- NeMo PII preview can fail with `503` when NVIDIA credentials are missing or `502` when the provider returns an error.
- OpenAI Guardrails PII preview can fail with `502` when local Presidio/spaCy initialization fails.
- Do not store sensitive preview inputs in browser local storage.

Common `400` validation details:

- `text must be a string.`
- `provider must be a string.`
- `provider must be one of: nemo, openai-guardrails`
- `language must be a string.`
- `score_threshold must be a number.`
- `score_threshold must be greater than 0 and less than or equal to 1.`
- `entities must be a list of strings.`
- `detect_encoded_pii must be a boolean.`
- `enable_pii must be a boolean.`
- `guardrails.enable_pii must be a boolean.`
- `guardrails.pii_provider must be a string.`
- `guardrails.pii_language must be a string.`
- `guardrails.pii_score_threshold must be a number.`
- `guardrails.pii_entities must be a list of strings.`
- `guardrails.pii_detect_encoded must be a boolean.`
- `Unsupported OpenAI Guardrails PII entities: ... Supported entities: ...`

## Suggested UI Copy

Use labels like:

- Deterministic masking
- PII detection
- Guardrails config
- Combined redaction preview
- PII provider

Avoid labels like:

- Policy management
- User keyword policy
- Business keyword detector
- Policy id

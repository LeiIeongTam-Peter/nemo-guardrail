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
- `/v1/pii/preview` for direct NeMo PII testing
- `/v1/redaction/preview` for deterministic plus optional PII preview
- `/v1/chat/completions` with `guardrails.config_id` and optional `guardrails.enable_pii`

The production redaction model is:

- built-in deterministic rules from `masking.yml`
- optional NeMo PII redaction with `guardrails.enable_pii`
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
- clear error state for missing or invalid NeMo credentials

## Behavioral Notes

Exact keyword lists are no longer treated as a production user workflow. They only work when the operator already knows the sensitive term before the user sends traffic, which does not scale for self-serve users.

The frontend should explain redaction as:

1. Deterministic masking catches known classes and configured deployment-wide patterns.
2. Optional NeMo PII detection catches supported PII entities.
3. Guardrails configs control conversational policy, topic boundaries, and self-check behavior.

Do not expose editable PII entity labels. The backend uses the configured NeMo server/model defaults.

Combined redaction always runs deterministic masking first, then NeMo PII detection. For example, if `masking.yml` already turns an email address into `[EMAIL]`, NeMo receives `[EMAIL]` instead of the raw email value.

`/v1/redaction/preview` defaults `enable_pii` to `true`. Chat only runs PII detection when the request explicitly includes `guardrails.enable_pii: true`.

## NeMo PII

The only supported PII provider is NeMo GLiNER-PII through NVIDIA hosted NIM or a local compatible endpoint. Hosted usage requires `NVIDIA_API_KEY` or `NEMO_PII_API_KEY`.

```ts
type PiiLanguage = "en" | "zh" | "zh-Hant" | "zh-Hans" | "auto";
```

Use the label `NeMo GLiNER-PII` in the UI. The frontend should not expose a provider selector or entity selector, and should not send `provider`, `entities`, `guardrails.pii_provider`, or `guardrails.pii_entities`.

The backend also ships a bilingual PII taxonomy in `pii_taxonomy.yml`. Use it to show Chinese/English keywords without hard-coding them in the frontend. It is descriptive metadata; `masking.yml` is still the executable deterministic rule set.

## PII Field Mapping

Preview endpoints use top-level PII fields:

```ts
type PreviewPiiFields = {
  language?: PiiLanguage;
  score_threshold?: number;
};
```

Chat uses the same options under `guardrails` with a `pii_` prefix:

```ts
type ChatGuardrailsFields = {
  config_id?: string;
  enable_pii?: boolean;
  pii_language?: PiiLanguage;
  pii_score_threshold?: number;
};
```

Backend-only PII fields are removed before the chat request is forwarded to NeMo/OpenAI.

NeMo language defaults to `auto`, which sends raw UTF-8 text to GLiNER without forcing English-only validation, so mixed Chinese/English input can be evaluated together. NeMo also accepts `en`, `zh`, `zh-Hant`, and `zh-Hans` as response metadata.

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

### List Bilingual PII Taxonomy

```http
GET /v1/pii/taxonomy
```

Response:

```ts
type PiiTaxonomyEntity = {
  id: string;
  placeholder: string;
  en_keywords: string[];
  zh_keywords: string[];
  deterministic_rule_names: string[];
};

type PiiTaxonomyResponse = {
  version: number;
  description: string;
  providers: Record<string, unknown>;
  entities: PiiTaxonomyEntity[];
};
```

Use this endpoint for UI presets such as "Chinese/Taiwan resume PII" and explanatory copy. Do not treat taxonomy keywords as a user-editable production policy engine.

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
  language?: PiiLanguage;
  score_threshold?: number;
};
```

NeMo request:

```json
{
  "language": "zh-Hant",
  "text": "姓名：王小明，Email：peter@example.com"
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
  provider: "nemo";
  engine: string;
  model: string;
  language: PiiLanguage;
  score_threshold: number;
  masked: string;
  entities: PiiEntity[];
  server_endpoint: string;
  tagged_text: string;
};
```

The frontend should omit `provider` and `entities`. If `provider` is supplied, the backend only accepts `nemo`. `score_threshold` must be greater than `0` and less than or equal to `1`.

### Preview Combined Redaction

```http
POST /v1/redaction/preview
Content-Type: application/json
```

```ts
type RedactionPreviewRequest = {
  text: string;
  enable_pii?: boolean;
  language?: PiiLanguage;
  score_threshold?: number;
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
  "score_threshold": 0.5
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
    "pii_score_threshold": 0.5
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
- Show NeMo credentials status when PII preview fails or succeeds.
- NeMo PII preview can fail with `503` when NVIDIA credentials are missing or `502` when the provider returns an error.
- Do not store sensitive preview inputs in browser local storage.

Common `400` validation details:

- `text must be a string.`
- `provider must be a string.`
- `provider must be 'nemo'.`
- `language must be a string.`
- `score_threshold must be a number.`
- `score_threshold must be greater than 0 and less than or equal to 1.`
- `entities is no longer supported. NeMo GLiNER-PII uses server default labels.`
- `enable_pii must be a boolean.`
- `guardrails.enable_pii must be a boolean.`
- `guardrails.pii_provider must be a string.`
- `guardrails.pii_language must be a string.`
- `guardrails.pii_score_threshold must be a number.`
- `guardrails.pii_entities is no longer supported. NeMo GLiNER-PII uses server default labels.`

## Suggested UI Copy

Use labels like:

- Deterministic masking
- PII detection
- Guardrails config
- Combined redaction preview
- NeMo GLiNER-PII

Avoid labels like:

- Policy management
- User keyword policy
- Business keyword detector
- Policy id

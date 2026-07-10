# Frontend Handoff: Policy Redaction API

## 這個 Service 是什麼

這個 service 是一個 NeMo Guardrails HTTP microservice。它提供 OpenAI-compatible chat API，並在 request 送進 NeMo/OpenAI 前、response 回到 client 前做 deterministic redaction。

目前 v1 的新功能是 **Policy Redaction**：

- 使用者可以建立多個 named `policy`。
- 每個 `policy` 包含一組 literal keywords，例如中文 `秘密專案`、英文 `client-name`。
- Chat request 每次可以指定 `guardrails.policy_id`。
- Service 會套用 built-in `masking.yml` rules，再追加該 policy 的 keywords。
- 命中的 keyword 會被替換成 policy 的 `replacement`，預設是 `[REDACTED]`。

這不是 semantic blocking，也不是 LLM-based moderation。v1 只做 deterministic keyword redaction。

## 前端要做什麼

建議前端做 3 個主要區塊：

1. **Policy List**
   - 顯示所有 policies。
   - 支援 create、edit、delete、enable/disable。

2. **Policy Editor**
   - 編輯 `id`、`name`、`description`、`enabled`、`replacement`、`case_sensitive`、`keywords`。
   - `keywords` 用 multiline textarea 或 tag input。
   - v1 不支援 regex，所有 keyword 都當 literal string。

3. **Policy Preview / Chat Tester**
   - Preview：輸入任意 JSON/text，呼叫 `/v1/policies/{policy_id}/preview`，顯示 redacted 結果。
   - Chat：呼叫 `/v1/chat/completions` 時讓使用者選 `config_id` 和 `policy_id`。

## Absolute Paths

Repo root:

```text
/Users/peter/Desktop/nemo-guardrail
```

API routes:

```text
/Users/peter/Desktop/nemo-guardrail/main.py
```

Policy schema、SQLite store、validation:

```text
/Users/peter/Desktop/nemo-guardrail/policies.py
```

Redaction middleware、built-in + policy keyword merge:

```text
/Users/peter/Desktop/nemo-guardrail/masking.py
```

Built-in masking rules:

```text
/Users/peter/Desktop/nemo-guardrail/masking.yml
```

NeMo guardrail configs:

```text
/Users/peter/Desktop/nemo-guardrail/configs/default
/Users/peter/Desktop/nemo-guardrail/configs/customer-support
/Users/peter/Desktop/nemo-guardrail/configs/resume-screening
```

Default SQLite DB path:

```text
/Users/peter/Desktop/nemo-guardrail/data/policies.sqlite3
```

Tests:

```text
/Users/peter/Desktop/nemo-guardrail/scripts/test_guardrails.py
```

## Base URL

Local default:

```text
http://localhost:8000
```

If running tests with temporary port:

```text
http://127.0.0.1:8010
```

## Data Schema

### Policy

```ts
type Policy = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  replacement: string;
  case_sensitive: boolean;
  keywords: string[];
  created_at: string;
  updated_at: string;
};
```

Validation rules:

- `id`: required, 1-64 chars, only `A-Z`, `a-z`, `0-9`, `_`, `-`.
- `name`: optional on create, defaults to `id`, max 128 chars.
- `description`: optional, max 500 chars.
- `enabled`: boolean, defaults to `true`.
- `replacement`: string, defaults to `[REDACTED]`, max 128 chars.
- `case_sensitive`: boolean, defaults to `false`.
- `keywords`: required non-empty array, max 500 items.
- each keyword: non-empty string, max 256 chars.
- Chinese keywords are supported.

### Policy Create Request

```ts
type CreatePolicyRequest = {
  id: string;
  name?: string;
  description?: string;
  enabled?: boolean;
  replacement?: string;
  case_sensitive?: boolean;
  keywords: string[];
};
```

Example:

```json
{
  "id": "resume-client-a",
  "name": "Resume Client A",
  "description": "Client-specific redaction keywords",
  "enabled": true,
  "replacement": "[REDACTED]",
  "case_sensitive": false,
  "keywords": ["秘密專案", "內部代號A", "client-name"]
}
```

### Policy Update Request

`PUT /v1/policies/{policy_id}` accepts a full or partial policy body. If `id` is included, it must match the path `policy_id`.

```ts
type UpdatePolicyRequest = Partial<CreatePolicyRequest>;
```

Recommended frontend behavior: send the full editor state on save.

### Error Response

```ts
type ErrorResponse = {
  detail: string;
};
```

Common status codes:

- `400`: validation error or disabled policy selected.
- `404`: policy not found.
- `409`: policy id already exists.

## API Endpoints

### List Policies

```http
GET /v1/policies
```

Debug request:

```bash
curl -X GET http://localhost:8000/v1/policies
```

Response:

```ts
type ListPoliciesResponse = {
  policies: Policy[];
};
```

### Create Policy

```http
POST /v1/policies
Content-Type: application/json
```

Request: `CreatePolicyRequest`

Debug request:

```bash
curl -X POST http://localhost:8000/v1/policies \
  -H "Content-Type: application/json" \
  -d '{
    "id": "resume-client-a",
    "name": "Resume Client A",
    "description": "Client-specific redaction keywords",
    "enabled": true,
    "replacement": "[REDACTED]",
    "case_sensitive": false,
    "keywords": ["秘密專案", "內部代號A", "client-name"]
  }'
```

Response: `Policy`

### Get Policy

```http
GET /v1/policies/{policy_id}
```

Debug request:

```bash
curl -X GET http://localhost:8000/v1/policies/resume-client-a
```

Response: `Policy`

### Update Policy

```http
PUT /v1/policies/{policy_id}
Content-Type: application/json
```

Request: `UpdatePolicyRequest`

Debug request:

```bash
curl -X PUT http://localhost:8000/v1/policies/resume-client-a \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Resume Client A Updated",
    "description": "Updated keyword policy",
    "enabled": true,
    "replacement": "[REDACTED]",
    "case_sensitive": false,
    "keywords": ["秘密專案", "內部代號A", "client-name", "new-keyword"]
  }'
```

Response: `Policy`

### Delete Policy

```http
DELETE /v1/policies/{policy_id}
```

Debug request:

```bash
curl -X DELETE http://localhost:8000/v1/policies/resume-client-a
```

Response:

```ts
type DeletePolicyResponse = {
  deleted: true;
  id: string;
};
```

### Preview Built-In Masking

```http
POST /v1/masking/preview
Content-Type: application/json
```

This previews only built-in `masking.yml` rules.

Request can be any JSON object:

```json
{
  "text": "Contact admin@example.com with OPENAI_API_KEY sk-test_abcdefghijklmnopqrstuvwxyz"
}
```

Debug request:

```bash
curl -X POST http://localhost:8000/v1/masking/preview \
  -H "Content-Type: application/json" \
  -d '{
    "text": "Contact admin@example.com with OPENAI_API_KEY sk-test_abcdefghijklmnopqrstuvwxyz"
  }'
```

Response:

```ts
type MaskingPreviewResponse = {
  enabled: boolean;
  masked: unknown;
};
```

### Preview Policy Redaction

```http
POST /v1/policies/{policy_id}/preview
Content-Type: application/json
```

This previews built-in rules + selected policy keywords.

Request can be any JSON object:

```json
{
  "text": "秘密專案 belongs to client-name and admin@example.com"
}
```

Debug request:

```bash
curl -X POST http://localhost:8000/v1/policies/resume-client-a/preview \
  -H "Content-Type: application/json" \
  -d '{
    "text": "秘密專案 belongs to client-name and admin@example.com"
  }'
```

Response:

```ts
type PolicyPreviewResponse = {
  enabled: boolean;
  policy_id: string;
  masked: unknown;
};
```

Example response:

```json
{
  "enabled": true,
  "policy_id": "resume-client-a",
  "masked": {
    "text": "[REDACTED] belongs to [REDACTED] and [EMAIL]"
  }
}
```

### Chat With Selected Policy

```http
POST /v1/chat/completions
Content-Type: application/json
```

Request shape follows the existing NeMo/OpenAI-compatible chat API. Frontend only needs to add `guardrails.policy_id`.

```ts
type ChatRequest = {
  model: string;
  messages: Array<{
    role: "system" | "user" | "assistant";
    content: string;
  }>;
  guardrails?: {
    config_id?: "default" | "customer-support" | "resume-screening" | string;
    policy_id?: string;
  };
};
```

Example:

```json
{
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
}
```

Debug request:

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

Important behavior:

- If `policy_id` is omitted, only built-in masking rules are applied.
- If `policy_id` exists, service applies policy keywords first, then built-in rules. This prevents policy keywords like `email` from corrupting built-in placeholders such as `[EMAIL]`.
- If policy keywords include `name`, `姓名`, or `名字`, the backend also redacts conservative name phrases such as `my name is Peter`, `my ame is Peter`, `I am Peter`, `Hi Peter!`, `your [REDACTED] is Peter`, and `我叫王小明`.
- The backend removes `policy_id` before passing the request to NeMo Guardrails.
- If `policy_id` does not exist, response is `404`.
- If the policy is disabled, response is `400`.

### Debug Chat Request Without Calling OpenAI

```http
POST /v1/policies/{policy_id}/debug-chat-request
Content-Type: application/json
```

This endpoint accepts the same request shape as `/v1/chat/completions`, but it does not call NeMo or OpenAI. It returns the request body after policy redaction and after removing `guardrails.policy_id`.

Use this endpoint before sending chat when debugging whether the AI can still see sensitive values.

Debug request:

```bash
curl -X POST http://localhost:8000/v1/policies/p2/debug-chat-request \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {
        "role": "user",
        "content": "my name is Peter, my email is lei23lei91@gmail.com"
      }
    ],
    "guardrails": {
      "config_id": "default",
      "policy_id": "p2"
    }
  }'
```

Example response:

```json
{
  "enabled": true,
  "policy_id": "p2",
  "forwarded_request": {
    "model": "gpt-4o-mini",
    "messages": [
      {
        "role": "user",
        "content": "my [REDACTED] is [REDACTED], my [REDACTED] is [EMAIL]"
      }
    ],
    "guardrails": {
      "config_id": "default"
    }
  }
}
```

## Frontend UX Notes

- Show a warning: "Policy redaction is exact keyword matching, not semantic blocking."
- Let users test Chinese and English keywords in preview before saving or before using chat.
- Use `case_sensitive: false` by default.
- For keyword input, trim whitespace and remove empty lines before sending.
- Warn users that short keywords match substrings. For example, keyword `name` redacts the `name` part of `client-name`.
- Tell users to restart the backend after backend code changes. Existing running servers keep the old masking behavior until restarted.
- Do not expose regex fields in v1.
- Do not store API keys or secrets in frontend local storage.
- Add a debug panel for API calls that shows the exact outgoing request: method, URL, headers, JSON body, status code, and response body.
- For chat debugging, call `/v1/policies/{policy_id}/debug-chat-request` first and show `forwarded_request` beside the original request.
- In debug panels, redact frontend-held secrets before display. Policy keywords themselves may be sensitive, so avoid persisting debug logs in browser storage.

## Debug Panel Shape

Recommended frontend debug object:

```ts
type DebugRequest = {
  method: "GET" | "POST" | "PUT" | "DELETE";
  url: string;
  headers: Record<string, string>;
  body?: unknown;
};

type DebugResponse = {
  status: number;
  body: unknown;
};
```

Example debug record for policy preview:

```json
{
  "request": {
    "method": "POST",
    "url": "http://localhost:8000/v1/policies/resume-client-a/preview",
    "headers": {
      "Content-Type": "application/json"
    },
    "body": {
      "text": "秘密專案 belongs to client-name and admin@example.com"
    }
  },
  "response": {
    "status": 200,
    "body": {
      "enabled": true,
      "policy_id": "resume-client-a",
      "masked": {
        "text": "[REDACTED] belongs to [REDACTED] and [EMAIL]"
      }
    }
  }
}
```

## Example Frontend Flow

1. Load policies with `GET /v1/policies`.
2. User creates/edits a policy.
3. Frontend sends `POST /v1/policies` or `PUT /v1/policies/{policy_id}`.
4. User enters sample text and clicks Preview.
5. Frontend calls `POST /v1/policies/{policy_id}/preview`.
6. In chat UI, user selects:
   - `config_id`: usually `resume-screening` for resume workflow.
   - `policy_id`: selected policy.
7. Frontend sends chat request to `/v1/chat/completions`.

## Test Commands

Run local tests without OpenAI:

```bash
cd /Users/peter/Desktop/nemo-guardrail
uv run python scripts/test_guardrails.py
```

Run HTTP smoke tests:

```bash
cd /Users/peter/Desktop/nemo-guardrail
PORT=8010 POLICY_DB_PATH=/tmp/nemo-guardrail-policy-test.sqlite3 uv run python main.py
uv run python scripts/test_guardrails.py --server-url http://127.0.0.1:8010
```

Do not run `--live` unless you intentionally want to call OpenAI and spend tokens.

import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Body, HTTPException
from fastapi.middleware.cors import CORSMiddleware

os.environ.setdefault("NEMO_GUARDRAILS_DISABLE_CHAT_UI", "true")

from masking import Masker, MaskingMiddleware, build_keyword_rules  # noqa: E402
from nemoguardrails.server import api  # noqa: E402
from nemoguardrails.telemetry import DeploymentTypeEnum, set_deployment_type  # noqa: E402
from policies import PolicyConflictError, PolicyStore, PolicyValidationError  # noqa: E402


BASE_DIR = Path(__file__).parent


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def create_app():
    config_dir = os.getenv("NEMO_GUARDRAILS_CONFIG_DIR", str(BASE_DIR / "configs"))
    default_config_id = os.getenv("NEMO_GUARDRAILS_DEFAULT_CONFIG_ID", "default")
    masking_config_path = os.getenv("MASKING_CONFIG_PATH", str(BASE_DIR / "masking.yml"))
    policy_db_path = os.getenv("POLICY_DB_PATH", str(BASE_DIR / "data" / "policies.sqlite3"))
    cors_allowed_origins = _split_csv(
        os.getenv(
            "CORS_ALLOWED_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000",
        )
    )
    mask_path_prefixes = _split_csv(
        os.getenv(
            "MASKING_PATH_PREFIXES",
            "/v1/chat/completions,/v1/checks",
        )
    )

    set_deployment_type(DeploymentTypeEnum.API.value)
    api.app.rails_config_path = os.path.expanduser(config_dir.rstrip(os.path.sep))
    api.set_default_config_id(default_config_id)

    masker = Masker.from_path(masking_config_path)
    policy_store = PolicyStore(policy_db_path)
    api.app.state.masker = masker
    api.app.state.policy_store = policy_store
    api.app.state.mask_path_prefixes = mask_path_prefixes
    api.app.add_middleware(
        MaskingMiddleware,
        masker=masker,
        path_prefixes=mask_path_prefixes,
        policy_loader=policy_store.get_policy,
    )
    api.app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @api.app.get("/v1/masking/rules")
    async def masking_rules():
        return {
            "enabled": masker.enabled,
            "rules": masker.rule_names,
            "path_prefixes": mask_path_prefixes,
        }

    @api.app.post("/v1/masking/preview")
    async def masking_preview(payload: dict[str, Any] = Body(...)):
        return {
            "enabled": masker.enabled,
            "masked": masker.mask_value(payload),
        }

    @api.app.post("/v1/policies", status_code=201)
    async def create_policy(payload: dict[str, Any] = Body(...)):
        try:
            return policy_store.create_policy(payload).to_dict()
        except PolicyConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except PolicyValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.app.get("/v1/policies")
    async def list_policies():
        return {"policies": [policy.to_dict() for policy in policy_store.list_policies()]}

    @api.app.get("/v1/policies/{policy_id}")
    async def get_policy(policy_id: str):
        policy = policy_store.get_policy(policy_id)
        if policy is None:
            raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
        return policy.to_dict()

    @api.app.put("/v1/policies/{policy_id}")
    async def update_policy(policy_id: str, payload: dict[str, Any] = Body(...)):
        try:
            policy = policy_store.update_policy(policy_id, payload)
        except PolicyValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if policy is None:
            raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
        return policy.to_dict()

    @api.app.delete("/v1/policies/{policy_id}")
    async def delete_policy(policy_id: str):
        if not policy_store.delete_policy(policy_id):
            raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
        return {"deleted": True, "id": policy_id}

    @api.app.post("/v1/policies/{policy_id}/preview")
    async def preview_policy(policy_id: str, payload: dict[str, Any] = Body(...)):
        policy = policy_store.get_policy(policy_id)
        if policy is None:
            raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
        if not policy.enabled:
            raise HTTPException(status_code=400, detail=f"Policy is disabled: {policy_id}")

        policy_masker = _masker_for_policy(masker, policy)
        return {
            "enabled": policy_masker.enabled,
            "policy_id": policy.id,
            "masked": policy_masker.mask_value(payload),
        }

    @api.app.post("/v1/policies/{policy_id}/debug-chat-request")
    async def debug_chat_request(policy_id: str, payload: dict[str, Any] = Body(...)):
        policy = policy_store.get_policy(policy_id)
        if policy is None:
            raise HTTPException(status_code=404, detail=f"Policy not found: {policy_id}")
        if not policy.enabled:
            raise HTTPException(status_code=400, detail=f"Policy is disabled: {policy_id}")

        forwarded_request = deepcopy(payload)
        guardrails = forwarded_request.get("guardrails")
        if isinstance(guardrails, dict):
            guardrails.pop("policy_id", None)

        policy_masker = _masker_for_policy(masker, policy)
        return {
            "enabled": policy_masker.enabled,
            "policy_id": policy.id,
            "forwarded_request": policy_masker.mask_value(forwarded_request),
        }

    return api.app


def _masker_for_policy(masker: Masker, policy):
    return masker.with_rules(
        build_keyword_rules(
            policy_id=policy.id,
            keywords=policy.keywords,
            replacement=policy.replacement,
            case_sensitive=policy.case_sensitive,
        ),
        prepend=True,
    )


def main():
    port = int(os.getenv("PORT", "8000"))
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()

import os
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Body

os.environ.setdefault("NEMO_GUARDRAILS_DISABLE_CHAT_UI", "true")

from masking import Masker, MaskingMiddleware  # noqa: E402
from nemoguardrails.server import api  # noqa: E402
from nemoguardrails.telemetry import DeploymentTypeEnum, set_deployment_type  # noqa: E402


BASE_DIR = Path(__file__).parent


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def create_app():
    config_dir = os.getenv("NEMO_GUARDRAILS_CONFIG_DIR", str(BASE_DIR / "configs"))
    default_config_id = os.getenv("NEMO_GUARDRAILS_DEFAULT_CONFIG_ID", "default")
    masking_config_path = os.getenv("MASKING_CONFIG_PATH", str(BASE_DIR / "masking.yml"))
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
    api.app.state.masker = masker
    api.app.state.mask_path_prefixes = mask_path_prefixes
    api.app.add_middleware(
        MaskingMiddleware,
        masker=masker,
        path_prefixes=mask_path_prefixes,
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

    return api.app


def main():
    port = int(os.getenv("PORT", "8000"))
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()

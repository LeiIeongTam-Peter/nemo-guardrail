import os
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import Body, HTTPException
from fastapi.middleware.cors import CORSMiddleware

os.environ.setdefault("NEMO_GUARDRAILS_DISABLE_CHAT_UI", "true")

from masking import (  # noqa: E402
    Masker,
    MaskingMiddleware,
)
from nemoguardrails.server import api  # noqa: E402
from nemoguardrails.telemetry import DeploymentTypeEnum, set_deployment_type  # noqa: E402
from pii import (  # noqa: E402
    DEFAULT_LANGUAGE,
    DEFAULT_SCORE_THRESHOLD,
    PiiConfigurationError,
    PiiDetector,
    PiiProviderError,
)


BASE_DIR = Path(__file__).parent


def _split_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def create_app():
    config_dir = os.getenv("NEMO_GUARDRAILS_CONFIG_DIR", str(BASE_DIR / "configs"))
    default_config_id = os.getenv("NEMO_GUARDRAILS_DEFAULT_CONFIG_ID", "default")
    masking_config_path = os.getenv("MASKING_CONFIG_PATH", str(BASE_DIR / "masking.yml"))
    cors_allowed_origins = _split_csv(
        os.getenv(
            "CORS_ALLOWED_ORIGINS",
            "http://localhost:3000,http://127.0.0.1:3000,"
            "http://localhost:3001,http://127.0.0.1:3001,"
            "http://localhost:3002,http://127.0.0.1:3002",
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
    pii_detector = PiiDetector()
    api.app.state.masker = masker
    api.app.state.pii_detector = pii_detector
    api.app.state.mask_path_prefixes = mask_path_prefixes
    api.app.add_middleware(
        MaskingMiddleware,
        masker=masker,
        path_prefixes=mask_path_prefixes,
        pii_detector=pii_detector,
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

    @api.app.post("/v1/pii/preview")
    async def pii_preview(payload: dict[str, Any] = Body(...)):
        (
            text,
            provider,
            language,
            score_threshold,
            entities,
            detect_encoded_pii,
        ) = _parse_pii_preview_payload(payload)

        try:
            return await pii_detector.preview(
                text=text,
                provider=provider,
                language=language,
                score_threshold=float(score_threshold),
                entities=entities,
                detect_encoded_pii=detect_encoded_pii,
            )
        except PiiConfigurationError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except PiiProviderError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @api.app.post("/v1/redaction/preview")
    async def redaction_preview(payload: dict[str, Any] = Body(...)):
        (
            text,
            provider,
            language,
            score_threshold,
            entities,
            detect_encoded_pii,
        ) = _parse_pii_preview_payload(payload)
        enable_pii = payload.get("enable_pii", True)
        if not isinstance(enable_pii, bool):
            raise HTTPException(status_code=400, detail="enable_pii must be a boolean.")

        if "policy_id" in payload:
            raise HTTPException(
                status_code=400,
                detail="policy_id is no longer supported. Use masking.yml rules or enable_pii.",
            )

        deterministic_masked = masker.mask_text(text)
        pii_result = None
        final_masked = deterministic_masked
        stages = ["deterministic"]
        pii_provider = provider

        if enable_pii:
            try:
                pii_result = await pii_detector.preview(
                    text=deterministic_masked,
                    provider=provider,
                    language=language,
                    score_threshold=score_threshold,
                    entities=entities,
                    detect_encoded_pii=detect_encoded_pii,
                )
            except PiiConfigurationError as exc:
                raise HTTPException(status_code=503, detail=str(exc)) from exc
            except PiiProviderError as exc:
                raise HTTPException(status_code=502, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

            final_masked = str(pii_result["masked"])
            pii_provider = str(pii_result.get("provider", provider or "pii"))
            stages.append(pii_provider)

        return {
            "enabled": True,
            "language": language,
            "score_threshold": score_threshold,
            "enable_pii": enable_pii,
            "pii_provider": pii_provider,
            "pii_detect_encoded": detect_encoded_pii,
            "stages": stages,
            "deterministic": {
                "enabled": masker.enabled,
                "masked": deterministic_masked,
            },
            "pii": pii_result,
            "masked": final_masked,
        }

    return api.app


def _parse_pii_preview_payload(
    payload: dict[str, Any],
) -> tuple[str, str | None, str, float, list[str] | None, bool]:
    text = payload.get("text")
    if not isinstance(text, str):
        raise HTTPException(status_code=400, detail="text must be a string.")

    provider = payload.get("provider")
    if provider is not None and not isinstance(provider, str):
        raise HTTPException(status_code=400, detail="provider must be a string.")

    language = payload.get("language", DEFAULT_LANGUAGE)
    if not isinstance(language, str):
        raise HTTPException(status_code=400, detail="language must be a string.")

    score_threshold = payload.get("score_threshold", DEFAULT_SCORE_THRESHOLD)
    if not isinstance(score_threshold, int | float):
        raise HTTPException(status_code=400, detail="score_threshold must be a number.")

    entities = payload.get("entities")
    if entities is not None and not (
        isinstance(entities, list) and all(isinstance(item, str) for item in entities)
    ):
        raise HTTPException(status_code=400, detail="entities must be a list of strings.")

    detect_encoded_pii = payload.get("detect_encoded_pii", False)
    if not isinstance(detect_encoded_pii, bool):
        raise HTTPException(status_code=400, detail="detect_encoded_pii must be a boolean.")

    return text, provider, language, float(score_threshold), entities, detect_encoded_pii


def main():
    port = int(os.getenv("PORT", "8000"))
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()

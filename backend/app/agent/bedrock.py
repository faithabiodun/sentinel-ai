"""Bedrock client: Claude conversation + Titan embeddings.

Intentionally thin — just boto3 with retry on throttle. The agent loop
owns all prompt construction; this module only knows about the wire format.
"""
from __future__ import annotations

import json
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

from ..config import settings

_runtime: Any = None


def _client() -> Any:
    global _runtime
    if _runtime is None:
        kwargs: dict[str, Any] = {"region_name": settings.aws_region}
        if settings.aws_access_key_id:
            kwargs["aws_access_key_id"] = settings.aws_access_key_id
            kwargs["aws_secret_access_key"] = settings.aws_secret_access_key
        _runtime = boto3.client("bedrock-runtime", **kwargs)
    return _runtime


def embed(text: str) -> list[float]:
    """Titan Text Embeddings v2 — 1024 dimensions."""
    body = json.dumps({"inputText": text[:8000], "dimensions": 1024, "normalize": True})
    for attempt in range(3):
        try:
            resp = _client().invoke_model(
                modelId=settings.bedrock_embed_model_id,
                body=body,
                contentType="application/json",
                accept="application/json",
            )
            return json.loads(resp["body"].read())["embedding"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ThrottlingException" and attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise


def converse(
    messages: list[dict],
    tools: list[dict],
    system: str,
    max_tokens: int = 4096,
) -> dict:
    """Claude converse API. Returns the raw response dict."""
    kwargs: dict[str, Any] = {
        "modelId": settings.bedrock_model_id,
        "messages": messages,
        "system": [{"text": system}],
        "inferenceConfig": {"maxTokens": max_tokens},
    }
    if tools:
        kwargs["toolConfig"] = {"tools": tools, "toolChoice": {"auto": {}}}

    for attempt in range(3):
        try:
            return _client().converse(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ThrottlingException" and attempt < 2:
                time.sleep(2 ** attempt)
                continue
            raise

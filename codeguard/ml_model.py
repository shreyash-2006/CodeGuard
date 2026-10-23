"""Backward-compatible shim — the model now lives in codeguard.ml.model."""
from codeguard.ml.model import (  # noqa: F401
    CATEGORIES,
    MultiLabelModel,
    ensure_model_ready,
    get_model,
)

MLModel = MultiLabelModel  # legacy alias

__all__ = ["MultiLabelModel", "MLModel", "CATEGORIES", "get_model", "ensure_model_ready"]

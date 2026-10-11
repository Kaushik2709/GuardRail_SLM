"""Default suite is offline; every successful model prediction is an explicit stub."""
import pytest
from app.core.slm_engine import SLMClassificationEngine
from app.core.heuristics import InspectionResult

@pytest.fixture(autouse=True)
def offline_classifier(monkeypatch, request):
    if request.node.get_closest_marker("model"):
        return
    async def classify(self, text):
        return InspectionResult(is_safe=True, tier="TEST_MODEL_STUB", confidence=0.0)
    monkeypatch.setattr(SLMClassificationEngine, "classify", classify)

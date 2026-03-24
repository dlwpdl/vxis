"""META-02 AdversarialAIAgent — model stealing, membership inference, misclassification attacks."""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class AdversarialAIAgent(BaseAgent):
    agent_id = "adversarial_ai"
    description = (
        "Adversarial ML testing: model extraction, membership inference, "
        "evasion attacks, misclassification, data poisoning assessment"
    )

    # Common ML model API endpoint patterns
    _ML_ENDPOINTS = [
        "/api/predict", "/api/classify", "/api/inference",
        "/v1/models", "/v1/predictions", "/predict",
        "/api/v1/predict", "/api/ml/infer", "/score",
        "/api/detect", "/api/analyze",
    ]

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Discover ML model endpoints
        endpoints = await self._discover_ml_endpoints(target)
        if endpoints:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"ML model endpoints discovered on {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=f"Active ML inference endpoints: {', '.join(endpoints)}",
                response=json.dumps(endpoints, indent=2),
                tags=["ai", "ml", "model-endpoint"],
            ))

        # Phase 2: Model information disclosure
        for endpoint in endpoints:
            model_info = await self._probe_model_info(target, endpoint)
            if model_info:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Model information disclosure on {endpoint}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "ML model metadata disclosed: architecture, version, "
                        "or framework information leaked via API response."
                    ),
                    response=json.dumps(model_info, indent=2)[:2000],
                    tags=["ai", "ml", "info-disclosure"],
                ))

        # Phase 3: Model extraction feasibility
        for endpoint in endpoints:
            extraction_risk = await self._assess_model_extraction(target, endpoint)
            if extraction_risk["feasible"]:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Model extraction feasible on {endpoint}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.EXPLOIT,
                    description=(
                        f"Model extraction attack is feasible. The endpoint returns "
                        f"confidence scores/probabilities allowing decision boundary "
                        f"mapping. Rate limiting: {extraction_risk['rate_limited']}. "
                        f"Estimated queries for extraction: {extraction_risk['est_queries']}"
                    ),
                    response=json.dumps(extraction_risk, indent=2),
                    tags=["ai", "ml", "model-extraction", "ip-theft"],
                ))
                hypotheses.append(Hypothesis(
                    title=f"Model stealing attack on {endpoint}",
                    rationale="Confidence scores returned without rate limiting",
                    probability=0.7,
                    impact=0.85,
                    suggested_agent="adversarial_ai",
                ))

        # Phase 4: Membership inference assessment
        for endpoint in endpoints:
            mi_result = await self._test_membership_inference(target, endpoint)
            if mi_result:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Membership inference risk on {endpoint}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.EXPLOIT,
                    description=(
                        "Model confidence distribution suggests membership inference "
                        "attacks may be feasible. High-confidence predictions for "
                        "specific inputs could reveal training data membership."
                    ),
                    response=json.dumps(mi_result, indent=2),
                    tags=["ai", "ml", "membership-inference", "privacy"],
                ))

        # Phase 5: Adversarial evasion probe
        for endpoint in endpoints:
            evasion = await self._test_evasion(target, endpoint)
            if evasion.get("evaded"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Adversarial evasion succeeded on {endpoint}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.EXPLOIT,
                    description=(
                        "Model classification was altered by adversarial perturbation. "
                        f"Original class: {evasion.get('original_class')}, "
                        f"Adversarial class: {evasion.get('adversarial_class')}"
                    ),
                    response=json.dumps(evasion, indent=2),
                    tags=["ai", "ml", "adversarial-evasion"],
                ))

        # Phase 6: Data poisoning surface assessment
        findings.append(Evidence(
            agent_id=self.agent_id,
            title=f"Data poisoning attack surface assessment for {target}",
            severity=Severity.INFO,
            evidence_type=EvidenceType.OTHER,
            description=(
                "Data poisoning assessment:\n"
                "- Check if model accepts feedback/corrections (reinforcement)\n"
                "- Check if training pipeline ingests user-submitted data\n"
                "- Check for public model fine-tuning APIs\n"
                "- Assess supply chain risk in training data sources"
            ),
            tags=["ai", "ml", "data-poisoning", "assessment"],
        ))

        hypotheses.append(Hypothesis(
            title=f"LLM prompt injection on AI services at {target}",
            rationale="ML model endpoints found — LLM services likely co-located",
            probability=0.6,
            impact=0.8,
            suggested_agent="ai_llm",
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "endpoints_found": len(endpoints),
                "extraction_feasible": sum(
                    1 for f in findings if "model-extraction" in f.tags
                ),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _discover_ml_endpoints(self, target: str) -> list[str]:
        if not shutil.which("curl"):
            return []
        active: list[str] = []
        for endpoint in self._ML_ENDPOINTS:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", "5", f"https://{target}{endpoint}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            code = stdout.decode().strip()
            if code and code not in ("000", "404", "502", "503"):
                active.append(endpoint)
        return active

    async def _probe_model_info(
        self, target: str, endpoint: str,
    ) -> dict[str, Any] | None:
        if not shutil.which("curl"):
            return None
        # Try GET for model metadata
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--max-time", "10",
            f"https://{target}{endpoint}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
        response = stdout.decode()
        try:
            data = json.loads(response)
            info_keys = ["model", "version", "framework", "architecture", "name"]
            info = {k: v for k, v in data.items() if k.lower() in info_keys}
            return info if info else None
        except (json.JSONDecodeError, AttributeError):
            return None

    async def _assess_model_extraction(
        self, target: str, endpoint: str,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "feasible": False,
            "rate_limited": True,
            "returns_confidence": False,
            "est_queries": 0,
        }
        if not shutil.which("curl"):
            return result

        # Send a benign prediction request and check if confidence scores returned
        test_payloads = [
            json.dumps({"input": "test input", "data": [0.1, 0.2, 0.3]}),
            json.dumps({"text": "benign test query"}),
        ]
        for payload in test_payloads:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", payload,
                f"https://{target}{endpoint}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            try:
                data = json.loads(stdout.decode())
                conf_keys = ["confidence", "probability", "score", "probabilities"]
                if any(k in str(data).lower() for k in conf_keys):
                    result["returns_confidence"] = True
                    result["feasible"] = True
                    result["est_queries"] = 10000  # rough estimate
                    break
            except json.JSONDecodeError:
                continue

        # Check rate limiting with a burst of requests
        success_count = 0
        for _ in range(5):
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", "3",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", test_payloads[0],
                f"https://{target}{endpoint}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            code = stdout.decode().strip()
            if code == "200":
                success_count += 1
            elif code == "429":
                break
        if success_count == 5:
            result["rate_limited"] = False
        return result

    async def _test_membership_inference(
        self, target: str, endpoint: str,
    ) -> dict[str, Any] | None:
        if not shutil.which("curl"):
            return None
        # Send queries and analyze confidence distribution
        payloads = [
            json.dumps({"input": f"test sample {i}"}) for i in range(3)
        ]
        confidences: list[float] = []
        for payload in payloads:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", payload,
                f"https://{target}{endpoint}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            try:
                data = json.loads(stdout.decode())
                # Try to extract confidence value
                for key in ("confidence", "score", "probability"):
                    if key in str(data).lower():
                        val = data.get(key, data.get(key.title(), None))
                        if isinstance(val, (int, float)):
                            confidences.append(float(val))
            except (json.JSONDecodeError, AttributeError):
                continue

        if len(confidences) >= 2:
            variance = sum((c - sum(confidences) / len(confidences)) ** 2
                           for c in confidences) / len(confidences)
            return {
                "confidences": confidences,
                "variance": round(variance, 6),
                "mi_risk": "high" if variance > 0.1 else "moderate",
            }
        return None

    async def _test_evasion(
        self, target: str, endpoint: str,
    ) -> dict[str, Any]:
        """Test basic adversarial evasion with perturbed inputs."""
        result: dict[str, Any] = {"evaded": False}
        if not shutil.which("curl"):
            return result

        # Original input
        original = json.dumps({"input": "normal benign input text"})
        # Perturbed input (unicode homoglyphs, zero-width chars)
        perturbed = json.dumps({
            "input": "n\u200borma\u200bl ben\u200bign in\u200bput te\u200bxt"
        })

        for label, payload in [("original", original), ("perturbed", perturbed)]:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "10",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", payload,
                f"https://{target}{endpoint}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            try:
                data = json.loads(stdout.decode())
                result[f"{label}_response"] = data
                for key in ("class", "label", "prediction", "category"):
                    if key in data:
                        result[f"{label}_class"] = data[key]
            except json.JSONDecodeError:
                continue

        if (result.get("original_class") and result.get("perturbed_class")
                and result["original_class"] != result["perturbed_class"]):
            result["evaded"] = True
            result["adversarial_class"] = result["perturbed_class"]
        return result

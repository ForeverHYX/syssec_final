"""Report model and scan orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .features import extract_features
from .rules import Finding, evaluate_rules


@dataclass(frozen=True)
class DetectorReport:
    apk_path: Path
    apk_sha256: str
    entry_count: int
    findings: list[Finding]

    @property
    def summary(self) -> dict[str, int]:
        categories = {"packer": 0, "obfuscation": 0, "environment": 0, "native": 0}
        for finding in self.findings:
            categories[finding.category] = categories.get(finding.category, 0) + 1
        return categories

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "apk": {
                "path": str(self.apk_path),
                "sha256": self.apk_sha256,
                "entry_count": self.entry_count,
            },
            "summary": self.summary,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_text(self) -> str:
        lines = [
            "HardenInspector report",
            f"APK: {self.apk_path}",
            f"SHA-256: {self.apk_sha256}",
            "Summary: "
            + ", ".join(f"{category}={count}" for category, count in self.summary.items()),
            "",
        ]
        if not self.findings:
            lines.append("No hardening indicators matched.")
            return "\n".join(lines)

        for finding in self.findings:
            lines.append(
                f"[{finding.category}] {finding.id} "
                f"({finding.severity}/{finding.confidence}): {finding.title}"
            )
            for evidence in finding.evidence[:5]:
                lines.append(f"  - {evidence.location}: {evidence.value}")
        return "\n".join(lines)


def scan_apk(path: str | Path) -> DetectorReport:
    features = extract_features(path)
    findings = evaluate_rules(features)
    return DetectorReport(
        apk_path=features.path,
        apk_sha256=features.sha256,
        entry_count=len(features.entries),
        findings=findings,
    )


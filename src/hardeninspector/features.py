"""Feature extraction from APK artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .apk import ApkArchive, FileEntry
from .axml import extract_axml_strings
from .dex import DexFile, MethodReference
from .util import extract_printable_strings, sha256_hex


@dataclass(frozen=True)
class StringEvidence:
    value: str
    location: str
    kind: str


@dataclass(frozen=True)
class ApkFeatures:
    path: Path
    sha256: str
    entries: list[FileEntry]
    manifest_strings: list[StringEvidence]
    dex_files: list[DexFile]
    native_strings: dict[str, list[str]]
    resource_entries: list[FileEntry]

    @property
    def string_evidence(self) -> list[StringEvidence]:
        evidence: list[StringEvidence] = list(self.manifest_strings)
        for dex in self.dex_files:
            evidence.extend(StringEvidence(value=value, location=f"{dex.name}:string", kind="dex-string") for value in dex.strings)
            evidence.extend(
                StringEvidence(value=value, location=f"{dex.name}:const-string", kind="dex-const-string")
                for value in dex.const_strings
            )
        for location, strings in self.native_strings.items():
            evidence.extend(StringEvidence(value=value, location=location, kind="native-string") for value in strings)
        return evidence

    @property
    def type_descriptors(self) -> list[str]:
        descriptors: list[str] = []
        for dex in self.dex_files:
            descriptors.extend(dex.type_descriptors)
        return descriptors

    @property
    def methods(self) -> list[MethodReference]:
        methods: list[MethodReference] = []
        for dex in self.dex_files:
            methods.extend(dex.methods)
        return methods

    @property
    def invoked_methods(self) -> list[MethodReference]:
        methods: list[MethodReference] = []
        for dex in self.dex_files:
            methods.extend(dex.invoked_methods)
        return methods


def extract_features(path: str | Path) -> ApkFeatures:
    apk_path = Path(path)
    archive = ApkArchive.open(apk_path)
    manifest_strings = _extract_manifest_strings(archive)
    dex_files = [DexFile.parse(entry.name, archive.read(entry.name)) for entry in archive.dex_files]
    native_strings = {
        entry.name: extract_printable_strings(archive.read(entry.name), min_length=4)
        for entry in archive.native_libraries
    }
    return ApkFeatures(
        path=apk_path,
        sha256=sha256_hex(apk_path.read_bytes()),
        entries=archive.entries,
        manifest_strings=manifest_strings,
        dex_files=dex_files,
        native_strings=native_strings,
        resource_entries=archive.resource_entries,
    )


def _extract_manifest_strings(archive: ApkArchive) -> list[StringEvidence]:
    if archive.manifest is None:
        return []
    values = extract_axml_strings(archive.manifest)
    if not values:
        values = extract_printable_strings(archive.manifest, min_length=4)
    return [
        StringEvidence(value=value, location="AndroidManifest.xml", kind="manifest-string")
        for value in values
    ]


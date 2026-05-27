"""APK ZIP inventory reader."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import zipfile

from .util import sha256_hex, shannon_entropy


@dataclass(frozen=True)
class FileEntry:
    name: str
    size: int
    compressed_size: int
    sha256: str
    entropy: float


@dataclass(frozen=True)
class ApkArchive:
    path: Path
    entries: list[FileEntry]
    files: dict[str, bytes]

    @classmethod
    def open(cls, path: str | Path) -> "ApkArchive":
        apk_path = Path(path)
        entries: list[FileEntry] = []
        files: dict[str, bytes] = {}
        with zipfile.ZipFile(apk_path) as apk:
            for info in apk.infolist():
                if info.is_dir():
                    continue
                data = apk.read(info.filename)
                files[info.filename] = data
                entries.append(
                    FileEntry(
                        name=info.filename,
                        size=info.file_size,
                        compressed_size=info.compress_size,
                        sha256=sha256_hex(data),
                        entropy=shannon_entropy(data),
                    )
                )
        return cls(path=apk_path, entries=entries, files=files)

    @property
    def manifest(self) -> bytes | None:
        return self.files.get("AndroidManifest.xml")

    @property
    def dex_files(self) -> list[FileEntry]:
        return [entry for entry in self.entries if _is_dex(entry.name)]

    @property
    def native_libraries(self) -> list[FileEntry]:
        return [entry for entry in self.entries if entry.name.startswith("lib/") and entry.name.endswith(".so")]

    @property
    def resource_entries(self) -> list[FileEntry]:
        return [
            entry
            for entry in self.entries
            if not _is_dex(entry.name)
            and entry.name != "AndroidManifest.xml"
            and not entry.name.startswith("lib/")
            and not entry.name.startswith("META-INF/")
        ]

    def get_entry(self, name: str) -> FileEntry | None:
        for entry in self.entries:
            if entry.name == name:
                return entry
        return None

    def read(self, name: str) -> bytes:
        return self.files[name]


def _is_dex(name: str) -> bool:
    return name == "classes.dex" or (name.startswith("classes") and name.endswith(".dex"))


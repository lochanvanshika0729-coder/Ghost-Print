"""Dataset CSV ingestion shared by the forensic backend components."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

log = logging.getLogger("ghostguard.ingestion")


@dataclass
class DatasetBundle:
    """All successfully parsed top-level CSV tables plus per-file load errors."""

    tables: dict[str, pd.DataFrame] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def table(self, name: str) -> pd.DataFrame:
        return self.tables.get(name, pd.DataFrame())

    def records(self, name: str) -> list[dict[str, str]]:
        frame = self.table(name)
        if frame.empty:
            return []
        return frame.to_dict(orient="records")


def load_datasets(dataset_dir: Path) -> DatasetBundle:
    """Read every top-level CSV with Pandas, preserving values as strings.

    Evidence file contents are handled separately by EvidenceReader. The
    evidence_files.csv manifest is included here like every other CSV table.
    Invalid/missing files are reported without preventing other tables loading.
    """
    directory = Path(dataset_dir).resolve()
    if not directory.is_dir():
        raise FileNotFoundError(f"Dataset directory does not exist: {directory}")

    result = DatasetBundle()
    for path in sorted(directory.glob("*.csv")):
        try:
            frame = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")
            result.tables[path.stem] = frame
        except (OSError, UnicodeError, ValueError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
            result.errors[path.name] = f"{type(exc).__name__}: {str(exc)[:200]}"
            log.warning("Could not load dataset CSV %s: %s", path.name, type(exc).__name__)
    if "evidence_files" not in result.tables:
        log.warning("evidence_files.csv was not loaded; evidence lookup will be unavailable")
    return result

import csv
import re
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import urlsplit

from app.dataset_models import NormalizedRequest


# Project root is the parent of the backend directory.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASETS_ROOT = PROJECT_ROOT / "datasets"

DATASET_FILES = {
    "wikimedia": DATASETS_ROOT / "wikimedia" / "raw" / "cache-t-00.tsv",
    "web_logs": DATASETS_ROOT / "web_log" / "access_log.txt",
    "synthetic": (
        DATASETS_ROOT / "synthetic" / "synthetic_attack_scenarios.csv"
    ),
}

DATASET_DESCRIPTIONS = {
    "wikimedia": "Wikimedia CDN request trace in TSV format.",
    "web_logs": "Apache-style HTTP access log.",
    "synthetic": "Generated request trace with labelled attack scenarios.",
}

# Apache combined/common log format, including the quoted request.
APACHE_LOG_PATTERN = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
)


class DatasetError(Exception):
    """Raised when a dataset name or dataset file is invalid."""


def get_dataset_path(dataset: str) -> Path:
    """Return the configured path for a supported dataset."""
    if dataset not in DATASET_FILES:
        available = ", ".join(sorted(DATASET_FILES))
        raise DatasetError(
            f"Unknown dataset '{dataset}'. Available datasets: {available}"
        )

    return DATASET_FILES[dataset]


def list_datasets() -> list[dict]:
    """List supported datasets and whether their files exist."""
    results = []

    for name, path in DATASET_FILES.items():
        results.append(
            {
                "name": name,
                "description": DATASET_DESCRIPTIONS[name],
                "file_exists": path.is_file(),
                "path": str(path),
            }
        )

    return results


def _safe_int(value, default: int = 0) -> int:
    try:
        number = int(float(value))
        return max(0, number)
    except (TypeError, ValueError, OverflowError):
        return default


def _safe_float(value) -> Optional[float]:
    try:
        number = float(value)
        return number if number >= 0 else None
    except (TypeError, ValueError, OverflowError):
        return None


def _parse_attack_label(value) -> Optional[bool]:
    if value is None:
        return None

    normalized = str(value).strip().lower()

    if normalized in {"1", "true", "yes", "attack"}:
        return True

    if normalized in {"0", "false", "no", "normal", "legitimate"}:
        return False

    return None


def _read_wikimedia(
    path: Path,
) -> Iterator[NormalizedRequest]:
    """
    Expected TSV columns:
    relative_unix, hashed_host_path_query, response_size, time_firstbyte
    """
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file, delimiter="\t")

        required = {
            "relative_unix",
            "hashed_host_path_query",
            "response_size",
            "time_firstbyte",
        }

        headers = set(reader.fieldnames or [])
        missing = required - headers

        if missing:
            raise DatasetError(
                "Wikimedia TSV is missing columns: "
                + ", ".join(sorted(missing))
            )

        for row_number, row in enumerate(reader, start=1):
            content_id = str(
                row.get("hashed_host_path_query", "")
            ).strip()

            timestamp = _safe_float(row.get("relative_unix"))
            response_size = _safe_int(row.get("response_size"))
            response_time = _safe_float(row.get("time_firstbyte"))

            if not content_id or timestamp is None:
                continue

            yield NormalizedRequest(
                dataset="wikimedia",
                request_id=f"wikimedia-{row_number}",
                timestamp=timestamp,
                content_id=content_id,
                response_size_bytes=response_size,
                response_time_seconds=response_time,
                method="GET",
            )


def _parse_apache_line(
    line: str,
    row_number: int,
) -> Optional[NormalizedRequest]:
    match = APACHE_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    request_parts = match.group("request").split()
    if len(request_parts) < 2:
        return None

    method = request_parts[0].upper()
    if not method.isalpha():
        return None

    parsed_target = urlsplit(request_parts[1])
    try:
        timestamp = datetime.strptime(
            match.group("timestamp"),
            "%d/%b/%Y:%H:%M:%S %z",
        ).timestamp()
    except ValueError:
        timestamp = None

    size_text = match.group("size")
    return NormalizedRequest(
        dataset="web_logs",
        request_id=f"apache-{row_number}",
        timestamp=timestamp,
        content_id=parsed_target.path or "/",
        response_size_bytes=(
            0 if size_text == "-" else _safe_int(size_text)
        ),
        client_id=match.group("client"),
        method=method,
        status_code=int(match.group("status")),
    )


def _read_apache(
    path: Path,
) -> Iterator[NormalizedRequest]:
    """Stream and parse Apache-style HTTP access logs."""
    with path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as file:
        for row_number, line in enumerate(file, start=1):
            record = _parse_apache_line(line, row_number)
            if record is not None:
                yield record


def _read_synthetic(
    path: Path,
) -> Iterator[NormalizedRequest]:
    """Read generated attack-scenario CSV records."""
    with path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        required = {
            "request_id",
            "timestamp",
            "content_id",
            "response_size",
            "scenario",
            "is_attack",
        }

        headers = set(reader.fieldnames or [])
        missing = required - headers

        if missing:
            raise DatasetError(
                "Synthetic CSV is missing columns: "
                + ", ".join(sorted(missing))
            )

        for row in reader:
            content_id = str(row.get("content_id", "")).strip()
            timestamp = _safe_float(row.get("timestamp"))

            if not content_id or timestamp is None:
                continue

            attack_label = _parse_attack_label(row.get("is_attack"))

            yield NormalizedRequest(
                dataset="synthetic",
                request_id=str(row.get("request_id", "")),
                timestamp=timestamp,
                content_id=content_id,
                response_size_bytes=_safe_int(
                    row.get("response_size")
                ),
                client_id=row.get("client_id") or None,
                scenario=row.get("scenario") or None,
                event_type=row.get("event_type") or None,
                is_attack=attack_label,
                method="GET",
            )


def iter_dataset(
    dataset: str,
    limit: Optional[int] = None,
) -> Iterator[NormalizedRequest]:
    """
    Yield normalized records without loading the entire dataset.

    limit counts valid normalized records, not malformed source rows.
    """
    path = get_dataset_path(dataset)

    if not path.is_file():
        raise DatasetError(
            f"Dataset file not found: {path}. "
            "Check the project folder structure."
        )

    readers = {
        "wikimedia": _read_wikimedia,
        "web_logs": _read_apache,
        "synthetic": _read_synthetic,
    }

    reader = readers[dataset](path)
    yielded = 0

    for record in reader:
        yield record
        yielded += 1

        if limit is not None and yielded >= limit:
            break


def preview_dataset(
    dataset: str,
    limit: int = 5,
) -> tuple[list[NormalizedRequest], int]:
    """
    Return normalized preview records and count malformed/skipped lines
    encountered before reaching the preview limit.

    This count is most meaningful for the Apache access log.
    """
    path = get_dataset_path(dataset)

    if not path.is_file():
        raise DatasetError(f"Dataset file not found: {path}")

    records: list[NormalizedRequest] = []
    skipped = 0

    if dataset == "web_logs":
        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as file:
            for row_number, line in enumerate(file, start=1):
                record = _parse_apache_line(line, row_number)
                if record is None:
                    skipped += 1
                    continue
                records.append(record)

                if len(records) >= limit:
                    break

        return records, skipped

    # For TSV and CSV, stream records and count records rejected by
    # the parser up to the requested preview size plus a safety window.
    # Parser generators skip malformed records internally, so the count
    # is not exposed as an exact total for these formats.
    records.extend(iter_dataset(dataset, limit=limit))
    return records, skipped
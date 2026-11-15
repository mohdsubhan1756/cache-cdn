import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any


DEFAULT_DATABASE_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "edgeguard_experiments.sqlite3"
)


class ExperimentStore:
    def __init__(self, database_path: str | Path | None = None):
        configured_path = database_path or os.getenv(
            "EDGEGUARD_EXPERIMENT_DB",
            str(DEFAULT_DATABASE_PATH),
        )
        self.database_path = Path(configured_path)
        self._lock = RLock()

        if str(self.database_path) != ":memory:":
            self.database_path.parent.mkdir(parents=True, exist_ok=True)

        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS experiment_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    configuration_json TEXT NOT NULL,
                    result_json TEXT NOT NULL
                )
                """
            )
            connection.commit()

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(str(self.database_path), timeout=10)
        try:
            yield connection
        finally:
            connection.close()

    def record_run(
        self,
        operation: str,
        configuration: dict[str, Any],
        result: dict[str, Any],
    ) -> dict[str, Any]:
        created_at = datetime.now(timezone.utc).isoformat()
        configuration_json = json.dumps(configuration, default=str)
        result_json = json.dumps(result, default=str)

        with self._lock, self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO experiment_runs (
                    created_at, operation, configuration_json, result_json
                ) VALUES (?, ?, ?, ?)
                """,
                (created_at, operation, configuration_json, result_json),
            )
            run_id = cursor.lastrowid
            connection.commit()

        return {
            "id": run_id,
            "created_at": created_at,
            "operation": operation,
            "configuration": configuration,
            "result": result,
        }

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(int(limit), 500))
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, created_at, operation,
                       configuration_json, result_json
                FROM experiment_runs
                ORDER BY id DESC
                LIMIT ?
                """,
                (bounded_limit,),
            ).fetchall()

        return [
            {
                "id": row[0],
                "created_at": row[1],
                "operation": row[2],
                "configuration": json.loads(row[3]),
                "result": json.loads(row[4]),
            }
            for row in rows
        ]


experiment_store = ExperimentStore()

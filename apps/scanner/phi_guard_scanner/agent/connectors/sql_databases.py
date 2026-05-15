from __future__ import annotations


def unsupported_database_connector(name: str) -> None:
    raise RuntimeError(
        f"{name} connector is registered in the scanner-agent contract but not enabled in this MVP build. "
        "Use PostgreSQL first, or implement the same metadata/sample adapter shape in this module."
    )

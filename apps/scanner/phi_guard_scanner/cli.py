from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from phi_guard_scanner.agent.contracts import ScanMode, SourceType
from phi_guard_scanner.agent.runner import scan_local_path, scan_postgres_source, scan_uri, submit_package
from phi_guard_scanner.demo import build_demo_intelligence


def main() -> None:
    parser = argparse.ArgumentParser(description="PHI Guard Intelligence scanner CLI")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    subcommands = parser.add_subparsers(dest="command", required=True)

    demo = subcommands.add_parser("demo", help="Emit the synthetic demo intelligence graph")
    demo.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    files = subcommands.add_parser("scan-files", help="Scan local files or a folder and emit a sanitized agent package")
    files.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    files.add_argument("--path", required=True, help="File or folder to scan")
    files.add_argument("--mode", choices=[mode.value for mode in ScanMode], default=ScanMode.MASKED_SAMPLE.value)
    files.add_argument("--workspace", default="Local File Scan")
    files.add_argument("--agent-id", default=os.getenv("PHI_GUARD_AGENT_ID", "local-dev-agent"))
    files.add_argument("--output", help="Optional JSON output path")

    postgres = subcommands.add_parser("scan-postgres", help="Scan PostgreSQL metadata and optional masked samples")
    postgres.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    postgres.add_argument("--dsn", default=os.getenv("PHI_GUARD_POSTGRES_DSN"), help="PostgreSQL DSN. Prefer env var in real use.")
    postgres.add_argument("--schema", action="append", default=["public"], help="Schema to include; repeat for more schemas")
    postgres.add_argument("--mode", choices=[mode.value for mode in ScanMode], default=ScanMode.METADATA_ONLY.value)
    postgres.add_argument("--workspace", default="PostgreSQL Scan")
    postgres.add_argument("--agent-id", default=os.getenv("PHI_GUARD_AGENT_ID", "local-dev-agent"))
    postgres.add_argument("--output", help="Optional JSON output path")

    source = subcommands.add_parser("scan-source", help="Scan by source type and URI")
    source.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    source.add_argument("--uri", required=True)
    source.add_argument("--source-type", choices=[source_type.value for source_type in SourceType], default=SourceType.FILES.value)
    source.add_argument("--mode", choices=[mode.value for mode in ScanMode], default=ScanMode.MASKED_SAMPLE.value)
    source.add_argument("--workspace", default="Agent Source Scan")
    source.add_argument("--agent-id", default=os.getenv("PHI_GUARD_AGENT_ID", "local-dev-agent"))
    source.add_argument("--output", help="Optional JSON output path")

    submit = subcommands.add_parser("submit", help="Submit a sanitized package to PHI Guard Intelligence API")
    submit.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    submit.add_argument("--package", required=True, help="Sanitized package JSON file")
    submit.add_argument("--api-url", default=os.getenv("PHI_GUARD_API_URL", "http://127.0.0.1:8000"))
    submit.add_argument("--agent-token", default=os.getenv("PHI_GUARD_AGENT_TOKEN"))
    args = parser.parse_args()

    if args.command == "demo":
        payload = build_demo_intelligence()
        _emit(payload, pretty=args.pretty)
    elif args.command == "scan-files":
        payload = scan_local_path(
            path=Path(args.path),
            mode=ScanMode(args.mode),
            project_name=args.workspace,
            agent_id=args.agent_id,
        )
        _emit(payload, pretty=args.pretty, output=args.output)
    elif args.command == "scan-postgres":
        if not args.dsn:
            parser.error("scan-postgres requires --dsn or PHI_GUARD_POSTGRES_DSN.")
        payload = scan_postgres_source(
            dsn=args.dsn,
            mode=ScanMode(args.mode),
            project_name=args.workspace,
            agent_id=args.agent_id,
            schemas=tuple(args.schema),
        )
        _emit(payload, pretty=args.pretty, output=args.output)
    elif args.command == "scan-source":
        payload = scan_uri(
            uri=args.uri,
            source_type=SourceType(args.source_type),
            mode=ScanMode(args.mode),
            project_name=args.workspace,
            agent_id=args.agent_id,
        )
        _emit(payload, pretty=args.pretty, output=args.output)
    elif args.command == "submit":
        if not args.agent_token:
            parser.error("submit requires --agent-token or PHI_GUARD_AGENT_TOKEN.")
        payload = json.loads(Path(args.package).read_text(encoding="utf-8"))
        response = submit_package(package=payload, api_url=args.api_url, agent_token=args.agent_token)
        _emit(response, pretty=args.pretty)


def _emit(payload: dict[str, object], *, pretty: bool, output: str | None = None) -> None:
    text = json.dumps(payload, indent=2 if pretty else None, sort_keys=True)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        return
    print(text)


if __name__ == "__main__":
    main()

from __future__ import annotations

from dataclasses import dataclass

from phi_guard_scanner.importers import ImportedColumn, ImportedTable, ImportResult, _build_scan_from_import
from phi_guard_scanner.models import to_plain


@dataclass(frozen=True)
class PostgresScanOptions:
    dsn: str
    project_name: str
    mode: str = "metadata_only"
    schemas: tuple[str, ...] = ("public",)
    sample_limit: int = 40


def scan_postgres(options: PostgresScanOptions) -> tuple[dict[str, object], list[str]]:
    try:
        import psycopg
        from psycopg import sql
    except ModuleNotFoundError as exc:
        raise RuntimeError("PostgreSQL scanning requires optional dependency psycopg. Install phi-guard-scanner[postgres].") from exc

    tables: list[ImportedTable] = []
    warnings: list[str] = []
    with psycopg.connect(options.dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT table_schema, table_name, column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = ANY(%s)
                ORDER BY table_schema, table_name, ordinal_position
                """,
                (list(options.schemas),),
            )
            columns_by_table: dict[tuple[str, str], list[tuple[str, str]]] = {}
            for schema_name, table_name, column_name, data_type in cursor.fetchall():
                columns_by_table.setdefault((schema_name, table_name), []).append((column_name, data_type))

            for (schema_name, table_name), columns in columns_by_table.items():
                imported_columns: list[ImportedColumn] = []
                row_count = _estimate_row_count(cursor, schema_name, table_name)
                for column_name, data_type in columns:
                    sample_values: list[str] = []
                    if options.mode != "metadata_only":
                        sample_values = _sample_column(cursor, sql, schema_name, table_name, column_name, options.sample_limit)
                    imported_columns.append(
                        ImportedColumn(
                            name=str(column_name),
                            data_type=str(data_type),
                            sample_values=sample_values,
                        )
                    )
                tables.append(
                    ImportedTable(
                        name=f"{schema_name}_{table_name}",
                        source_path=f"postgres://{schema_name}.{table_name}",
                        source_format="postgres",
                        row_count_estimate=row_count,
                        columns=imported_columns,
                    )
                )
    result = ImportResult(project_name=options.project_name, tables=tables, warnings=warnings, parsed_files=["postgres://metadata"])
    return to_plain(_build_scan_from_import(result)), warnings


def _estimate_row_count(cursor, schema_name: str, table_name: str) -> int:
    cursor.execute(
        """
        SELECT COALESCE(c.reltuples::bigint, 0)
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = %s AND c.relname = %s
        """,
        (schema_name, table_name),
    )
    row = cursor.fetchone()
    return max(0, int(row[0])) if row else 0


def _sample_column(cursor, sql, schema_name: str, table_name: str, column_name: str, limit: int) -> list[str]:
    query = sql.SQL("SELECT {column}::text FROM {schema}.{table} WHERE {column} IS NOT NULL LIMIT %s").format(
        schema=sql.Identifier(schema_name),
        table=sql.Identifier(table_name),
        column=sql.Identifier(column_name),
    )
    cursor.execute(query, (limit,))
    return [str(row[0])[:500] for row in cursor.fetchall() if row[0] is not None]

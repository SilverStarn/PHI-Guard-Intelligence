from __future__ import annotations

from pathlib import Path

from phi_guard_scanner.importers import MAX_PROJECT_FILES, MAX_UPLOAD_BYTES, SUPPORTED_EXTENSIONS, UploadedInput, build_uploaded_intelligence


SKIPPED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
}


def scan_path(path: Path, project_name: str) -> tuple[dict[str, object], list[str]]:
    warnings: list[str] = []
    inputs: list[UploadedInput] = []
    for file_path in _iter_files(path):
        if len(inputs) >= MAX_PROJECT_FILES:
            warnings.append(f"Stopped after {MAX_PROJECT_FILES} files to keep the local agent scan bounded.")
            break
        suffix = file_path.suffix.lower()
        if suffix not in SUPPORTED_EXTENSIONS:
            continue
        size = file_path.stat().st_size
        if size > MAX_UPLOAD_BYTES:
            warnings.append(f"Skipped {file_path}: file exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
            continue
        inputs.append(UploadedInput(filename=_display_path(file_path, path), content=file_path.read_bytes()))

    if not inputs:
        warnings.append(f"No supported files found under {path}.")
    return build_uploaded_intelligence(inputs, project_name=project_name), warnings


def _iter_files(path: Path):
    resolved = path.expanduser().resolve()
    if resolved.is_file():
        yield resolved
        return
    for file_path in resolved.rglob("*"):
        if any(part in SKIPPED_DIRS for part in file_path.parts):
            continue
        if file_path.is_file():
            yield file_path


def _display_path(file_path: Path, root: Path) -> str:
    try:
        return str(file_path.relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return file_path.name

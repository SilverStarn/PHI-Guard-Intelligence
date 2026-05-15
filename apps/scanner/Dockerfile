FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
WORKDIR /opt/phi-guard

COPY apps/scanner/pyproject.toml ./apps/scanner/pyproject.toml
COPY apps/scanner/phi_guard_scanner ./apps/scanner/phi_guard_scanner

ENV PYTHONPATH=/opt/phi-guard/apps/scanner

ENTRYPOINT ["python", "-m", "phi_guard_scanner.cli"]
CMD ["--help"]

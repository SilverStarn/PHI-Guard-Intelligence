FROM python:3.12-slim

WORKDIR /app

COPY apps/api/requirements.txt apps/api/requirements.txt
RUN pip install --no-cache-dir -r apps/api/requirements.txt

COPY apps/api apps/api
COPY apps/scanner apps/scanner

ENV PYTHONPATH=/app/apps/scanner
EXPOSE 8000

CMD ["uvicorn", "apps.api.app.main:app", "--host", "0.0.0.0", "--port", "8000"]


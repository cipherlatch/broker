FROM python:3.13-slim

WORKDIR /srv/app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .
COPY scripts ./scripts

EXPOSE 8000
CMD ["sh", "-c", "python -m scripts.migrate && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

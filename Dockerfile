FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock* ./
RUN uv sync --frozen --no-dev

COPY configs ./configs
COPY main.py ./main.py
COPY masking.py ./masking.py
COPY pii.py ./pii.py
COPY masking.yml ./masking.yml

EXPOSE 8000

CMD ["uv", "run", "--no-sync", "python", "main.py"]

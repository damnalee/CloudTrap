FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CLOUDTRAP_DATA_DIR=/data/processed

WORKDIR /app
COPY app.py /app/app.py

RUN useradd --system --uid 10001 --no-create-home cloudtrap
USER 10001:10001

EXPOSE 8501
ENTRYPOINT ["python", "/app/app.py", "--host", "0.0.0.0", "--port", "8501"]

FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir flask authlib werkzeug cryptography substrate-interface flask-cors
COPY . .

CMD ["python", "app.py"]
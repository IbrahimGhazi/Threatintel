FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Fetch Tranco Top 100k popular-domains list at build time.
# Used by the reputation scorer to suppress alerts on traffic to
# well-known domains. Falls back to an empty list on network failure
# (scorer simply disables the tranco signal if the list is missing).
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && mkdir -p /app/data \
    && ( \
         curl -fsSL --max-time 60 "https://tranco-list.eu/top-1m.csv.zip" -o /tmp/tranco.zip \
         && unzip -p /tmp/tranco.zip top-1m.csv | head -100000 | cut -d, -f2 > /app/data/tranco_top100k.txt \
         && rm /tmp/tranco.zip \
         && echo "Tranco Top 100k loaded: $(wc -l < /app/data/tranco_top100k.txt) domains" \
       ) \
    || ( \
         echo "Tranco download failed; shipping empty list (scorer will disable popular-domain signal)" \
         && : > /app/data/tranco_top100k.txt \
       ) \
    && apt-get purge -y --auto-remove curl unzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

CMD ["python", "-m", "main"]

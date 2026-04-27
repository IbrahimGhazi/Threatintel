# ============================================================
# TI Platform – Developer Makefile
# ============================================================

.PHONY: help up down logs ps build pull test shell-api shell-db clean

help:
	@echo "TI Platform commands:"
	@echo ""
	@echo "  make up          Start all services"
	@echo "  make down        Stop all services"
	@echo "  make build       Rebuild Docker images"
	@echo "  make pull        Pull latest base images"
	@echo "  make logs        Tail logs for all services"
	@echo "  make ps          Show service status"
	@echo "  make test        Run all unit tests"
	@echo "  make shell-api   Open shell in API container"
	@echo "  make shell-db    Open psql in PostgreSQL"
	@echo "  make clean       Remove volumes (DESTRUCTIVE)"
	@echo ""

# Copy .env.example if .env doesn't exist
.env:
	@cp .env.example .env
	@echo "Created .env from .env.example – please edit it before starting."

up: .env
	docker compose up -d
	@echo ""
	@echo "Platform started. Access:"
	@echo "  Frontend:   http://localhost"
	@echo "  API docs:   http://localhost/api/docs (dev mode only)"
	@echo "  Grafana:    http://localhost:3001"
	@echo "  Prometheus: http://localhost:9090"

down:
	docker compose down

build:
	docker compose build

pull:
	docker compose pull

logs:
	docker compose logs -f --tail=100

ps:
	docker compose ps

test:
	@echo "── API tests ──────────────────────────────────"
	docker compose run --rm api python -m pytest tests/ -v
	@echo "── Ingestion tests ────────────────────────────"
	docker compose run --rm ingestion python -m pytest tests/ -v
	@echo "── ICAP tests ─────────────────────────────────"
	docker compose run --rm icap python -m pytest tests/ -v
	@echo "── Correlation tests ──────────────────────────"
	docker compose run --rm correlation python -m pytest tests/ -v

shell-api:
	docker compose exec api bash

shell-db:
	docker compose exec postgres psql -U $${POSTGRES_USER:-tiplatform} -d $${POSTGRES_DB:-tiplatform}

clean:
	@echo "WARNING: This will destroy all data volumes!"
	@read -p "Type 'yes' to confirm: " confirm; \
	if [ "$$confirm" = "yes" ]; then \
		docker compose down -v; \
	fi

# Download GeoIP databases (requires MAXMIND_LICENSE_KEY env var)
geoip:
	@if [ -z "$$MAXMIND_LICENSE_KEY" ]; then \
		echo "Set MAXMIND_LICENSE_KEY env var first"; exit 1; \
	fi
	@mkdir -p geoip
	curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$$MAXMIND_LICENSE_KEY&suffix=tar.gz" | \
		tar xz --strip-components=1 -C geoip --wildcards "*.mmdb"
	curl -sL "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=$$MAXMIND_LICENSE_KEY&suffix=tar.gz" | \
		tar xz --strip-components=1 -C geoip --wildcards "*.mmdb"
	@echo "GeoIP databases downloaded to ./geoip/"

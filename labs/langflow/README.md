# Langflow Lab (B Node)

CVE-2025-3248 vulnerable lab for ChainGuard attack-defense experiment.

## Version

| Component | Version | Notes |
|---|---|---|
| Langflow | 1.2.0 | Vulnerable (< 1.3.0) |
| Docker image | `langflowai/langflow:1.2.0` | Pinned, no `latest` |

## Quick Start

```bash
# Copy env template
cp .env.example .env

# Start
docker compose up -d

# Health check
bash healthcheck.sh

# View logs
docker compose logs -f

# Restart
docker compose restart

# Stop
docker compose down
```

## Network Binding

> **IMPORTANT**: The service is currently bound to `192.168.44.136` for development.
> After the lab network segment `10.10.10.0/24` is provisioned by P1, change the port binding in `compose.yml` to:
> ```yaml
> ports:
>   - "10.10.10.2:7860:7860"
> ```
> Also update the `TARGET` in `healthcheck.sh` and `.env` accordingly.

## Structure

```
labs/langflow/
├── compose.yml       # Docker Compose (pinned 1.2.0)
├── .env.example      # Env template (no secrets)
├── healthcheck.sh    # Health check script
└── README.md         # This file
```

## Image Digest

| Field | Value |
|---|---|
| RepoDigest | langflowai/langflow@sha256:1e9cfdb0e1565b1187bdd3c6849493ecbd81627645214ab0537d7cbcdbdb454a |
| Image ID | sha256:3c41de86af41001f00cfa07384726a0246974a599f556ef658377d817a270a10 |

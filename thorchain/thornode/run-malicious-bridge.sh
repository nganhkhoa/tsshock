#!/bin/bash
docker compose -f build/docker/docker-compose.yml --profile mocknet-cluster --profile midgard up bifrost-cat


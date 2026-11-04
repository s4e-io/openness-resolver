#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(tr -d '[:space:]' <VERSION)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X github.com/s4e-io/openness-resolver/internal/buildinfo.Version=${VERSION} -X github.com/s4e-io/openness-resolver/internal/buildinfo.Commit=${COMMIT} -X github.com/s4e-io/openness-resolver/internal/buildinfo.Date=${DATE}"

mkdir -p dist bin

echo "building version=${VERSION} commit=${COMMIT}"

echo "building linux/arm64..."
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "dist/openness-resolver_${VERSION}_linux_arm64" ./cmd/openness-resolver

echo "building linux/amd64..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "dist/openness-resolver_${VERSION}_linux_amd64" ./cmd/openness-resolver

echo "building darwin/arm64 (local)..."
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "dist/openness-resolver_${VERSION}_darwin_arm64" ./cmd/openness-resolver

echo "building local bin/openness-resolver..."
CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o bin/openness-resolver ./cmd/openness-resolver

ls -lh dist/ bin/openness-resolver

SHELL := /bin/bash

.PHONY: up down test-backend test-web build-web
up:
	docker compose -f docker/compose.yml up --build -d
down:
	docker compose -f docker/compose.yml down
test-backend:
	dotnet test tests/backend/TemporalMark.Domain.Tests/TemporalMark.Domain.Tests.csproj
	dotnet test tests/backend/TemporalMark.Business.Tests/TemporalMark.Business.Tests.csproj
test-web:
	cd tests/frontend && npm install && npx playwright test
build-web:
	cd src/frontend && npm install && npm run build

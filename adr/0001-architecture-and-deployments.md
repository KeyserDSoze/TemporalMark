# ADR 0001 — Modular monolith, DDD and deployment portability

Status: Accepted (2026-11-15)

## Context
TemporalMark must have one bounded context (Time Stamping), .NET 10 HTTP APIs, an administrative React/TypeScript PWA, and both on-premises open-source and Azure deployments.

## Decision
Use a modular monolith organized as:
- `src/backend/domains/TemporalMark.Domain`: business invariants and entities; no infrastructure dependencies.
- `src/backend/business/TemporalMark.Business`: application services, ports and use cases.
- `src/backend/infrastructures/TemporalMark.Infrastructure`: PostgreSQL, storage, external TSA/HSM and infrastructure adapters.
- `src/backend/applications/TemporalMark.Api`: ASP.NET Core 10, authentication, authorization and HTTP endpoints.
- `src/frontend`: React, TypeScript, Vite, shadcn/ui conventions, Tailwind, i18n, PWA.
- `tests/backend` and `tests/frontend`: xUnit and Playwright.

One deployment unit can serve multiple tenants; no tenant-specific compilation. PostgreSQL is common across environments. Adapters isolate identity, object storage, signing/HSM, time authority, messaging and observability. On-prem production targets PostgreSQL + Keycloak + a separately validated WORM-compatible storage and HSM/time appliances. Azure targets managed PostgreSQL, Microsoft Entra External ID or another approved IdP, Azure Blob immutable storage and a CAB-accepted HSM/time topology.

## Consequences
A containerized local environment tests the application, **not QTSP compliance**. Reference cloud resources are not a guarantee of audit acceptance. Maintain a decision/evidence register and a change-controlled production baseline.

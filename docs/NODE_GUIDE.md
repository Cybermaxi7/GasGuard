# GasGuard Node.js Development Guide

## Structure
- **apps/node/**: Backend services (NestJS) or frontends.
- **libs/node/**: Shared libraries.
- **packages/**: Shared tooling (e.g., TSConfig).

## Workflow
This project uses **pnpm workspaces**.

To run a command across all packages:
```bash
pnpm -r run <command>
```

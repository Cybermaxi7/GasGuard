# GasGuard System Architecture

## Monorepo Strategy
We use a polyglot monorepo approach:
- **Rust** is used for high-performance computation and smart contract analysis.
- **Node.js** is used for API orchestration and web interfaces.

Both languages coexist with shared tooling for CI/CD and deployment.

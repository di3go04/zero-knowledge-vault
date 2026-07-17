# Contributing to Zero-Knowledge Vault

Thank you for considering contributing to this project. Please follow these guidelines to ensure a smooth process.

## Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/your-org/zk-vault.git
   cd zk-vault
   ```

2. Install dependencies:

   ```bash
   bun install
   ```

3. Set up environment variables:

   ```bash
   cp .env.example .env
   ```

   Then fill in the required values in `.env`.

4. Start the development server:
   ```bash
   bun run dev
   ```

## Code Quality

- Run tests before submitting: `bun run test`
- Lint your code: `bun run lint`
- Ensure type-checking passes: `bun run typecheck`
- All new features must include tests.

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `style`, `perf`, `ci`, `build`.

## Pull Request Process

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Commit your changes following the commit convention.
3. Push the branch and open a pull request.
4. Ensure all CI checks pass.
5. Request review from a maintainer.

## Reporting Issues

Search existing issues before creating a new one. Provide clear reproduction steps, expected behavior, and actual behavior.

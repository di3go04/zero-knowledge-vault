# ZK Vault — CLI (Bun)

## Usage

```bash
bun run src/cli/index.ts login
bun run src/cli/index.ts list
bun run src/cli/index.ts get <secret-id>
bun run src/cli/index.ts create
bun run src/cli/index.ts rotate
bun run src/cli/index.ts logout
```

Or make it executable:
```bash
chmod +x src/cli/index.ts
./src/cli/index.ts help
```

## Structure

```
src/cli/
├── index.ts          # Entry point — command dispatch
├── command.ts        # Command implementations
├── api-client.ts     # HTTP client for vault API
├── session.ts        # Session token persistence (~/.zk-vault/session.json)
└── prompt.ts         # Interactive prompts (password input, multi-line)
```

## Environment

- `VAULT_API_URL` — API base URL (default: http://localhost:3000)

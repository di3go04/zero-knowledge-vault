# @zk-vault/cli

CLI tool for Zero-Knowledge Vault — manage secrets from the terminal.

## Install

```bash
npm install -g @zk-vault/cli
# or
bun add -g @zk-vault/cli
```

## Usage

```bash
# Login to your vault
zk-vault login user@example.com

# List all secrets
zk-vault list

# Create a new secret
zk-vault create "GitHub Token" '{"username":"octocat","password":"ghp_xxx"}'

# Export vault
zk-vault export backup.json
```

## Environment Variables

- `VAULT_URL` — Base URL of your ZK Vault instance (default: http://localhost:3000)

## License

MIT

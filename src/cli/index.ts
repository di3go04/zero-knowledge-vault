#!/usr/bin/env bun
/**
 * Zero-Knowledge Vault — CLI (Bun)
 *
 * Commands:
 *   vault list          List all secrets
 *   vault get <id>      Get a secret's decrypted content
 *   vault create        Create a new secret (interactive)
 *   vault rotate        Rotate master password
 *   vault login         Authenticate with the vault API
 *   vault logout        Clear session
 */

import { Command } from "./command";

const [cmd, ...args] = process.argv.slice(2);

async function main() {
  const command = new Command();

  switch (cmd) {
    case "login":
      await command.login();
      break;
    case "logout":
      await command.logout();
      break;
    case "list":
      await command.list();
      break;
    case "get":
      if (!args[0]) {
        console.error("Usage: vault get <secret-id>");
        process.exit(1);
      }
      await command.get(args[0]);
      break;
    case "create":
      await command.create();
      break;
    case "rotate":
      await command.rotate();
      break;
    case "help":
    case undefined:
      showHelp();
      break;
    default:
      console.error(`Unknown command: ${cmd}`);
      showHelp();
      process.exit(1);
  }
}

function showHelp() {
  console.log(`
Zero-Knowledge Vault CLI — Gestor de contraseñas desde terminal

Usage:
  vault login          Iniciar sesión
  vault logout         Cerrar sesión
  vault list           Listar secretos
  vault get <id>       Mostrar secreto
  vault create         Crear secreto (interactivo)
  vault rotate         Rotar contraseña maestra
  vault help           Mostrar esta ayuda
`);
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});

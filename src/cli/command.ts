import { api } from "./api-client";
import { session } from "./session";
import { prompt, readStdin } from "./prompt";

export class Command {
  async login(): Promise<void> {
    const email = await prompt("Email: ");
    const password = await prompt("Contraseña maestra: ", { silent: true });

    const res = await api.login(email, password);
    session.save(res.token, res.userId);
    console.log("Sesión iniciada como", email);
  }

  async logout(): Promise<void> {
    session.clear();
    console.log("Sesión cerrada.");
  }

  async list(): Promise<void> {
    const token = session.load();
    if (!token) {
      console.error("No hay sesión activa. Ejecuta 'vault login' primero.");
      process.exit(1);
    }

    const secrets = await api.listSecrets(token);
    if (secrets.data.length === 0) {
      console.log("No hay secretos.");
      return;
    }

    for (const s of secrets.data) {
      console.log(`${s.id.padEnd(36)} ${s.title}`);
    }
  }

  async get(id: string): Promise<void> {
    const token = session.load();
    if (!token) {
      console.error("No hay sesión activa. Ejecuta 'vault login' primero.");
      process.exit(1);
    }

    const secret = await api.getSecret(token, id);
    console.log("ID:", secret.id);
    console.log("Título:", secret.title);
    console.log("Creado:", secret.createdAt);
    if (secret.encryptedData) {
      console.log("\nDatos cifrados (base64):");
      console.log(secret.encryptedData);
    }
  }

  async create(): Promise<void> {
    const token = session.load();
    if (!token) {
      console.error("No hay sesión activa. Ejecuta 'vault login' primero.");
      process.exit(1);
    }

    const title = await prompt("Título: ");
    console.log("Contenido (Ctrl+D para finalizar):");
    const content = await readStdin();

    const result = await api.createSecret(token, title, content);
    console.log("Secreto creado con ID:", result.id);
  }

  async rotate(): Promise<void> {
    const token = session.load();
    if (!token) {
      console.error("No hay sesión activa. Ejecuta 'vault login' primero.");
      process.exit(1);
    }

    const oldPassword = await prompt("Contraseña actual: ", { silent: true });
    const newPassword = await prompt("Nueva contraseña: ", { silent: true });
    const confirm = await prompt("Confirmar nueva contraseña: ", { silent: true });

    if (newPassword !== confirm) {
      console.error("Las contraseñas no coinciden.");
      process.exit(1);
    }

    await api.rotatePassword(token, oldPassword, newPassword);
    console.log("Contraseña rotada exitosamente.");
  }
}

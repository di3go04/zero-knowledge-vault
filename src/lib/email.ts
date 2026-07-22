import { logger } from "./logger";

interface EmailPayload {
  to: string;
  subject: string;
  text: string;
  html?: string;
}

const smtpHost = process.env.SMTP_HOST;
const smtpPort = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : 587;
const smtpUser = process.env.SMTP_USER;
const smtpPass = process.env.SMTP_PASS;
const fromEmail = process.env.SMTP_FROM ?? "noreply@zkvault.app";

export async function sendEmail(payload: EmailPayload): Promise<void> {
  if (smtpHost && smtpUser && smtpPass) {
    try {
      const nodemailer = await import("nodemailer");
      const transporter = nodemailer.default.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: { user: smtpUser, pass: smtpPass },
      });
      await transporter.sendMail({
        from: fromEmail,
        to: payload.to,
        subject: payload.subject,
        text: payload.text,
        html: payload.html,
      });
      logger.info({ to: payload.to, subject: payload.subject }, "email sent via SMTP");
    } catch (err) {
      logger.error({ err, to: payload.to }, "email send failed via SMTP — falling back to log");
      logger.warn({ to: payload.to, subject: payload.subject, text: payload.text }, "[email fallback]");
    }
  } else {
    logger.info(
      { to: payload.to, subject: payload.subject, text: payload.text },
      "[email] no SMTP configured — logged only. Set SMTP_HOST, SMTP_USER, SMTP_PASS to send real emails.",
    );
  }
}

"use client";
import { Component, type ReactNode, type ReactElement } from "react";

interface State {
  hasError: boolean;
  error?: Error;
}

interface Props {
  children: ReactNode;
  /**
   * Render-prop opcional para mostrar UI personalizada cuando ocurre
   * un error. Recibe `{ error, reset }` donde `reset` limpia el
   * estado del boundary (re-intenta renderizar children).
   *
   * Si no se pasa, se renderiza un fallback genérico.
   */
  fallback?: (props: { error: Error | undefined; reset: () => void }) => ReactElement;
}

/**
 * ErrorBoundary con render-prop fallback.
 *
 * Uso típico (Módulo 2 — atrapar errores criptográficos de payloads
 * corruptos):
 *
 *   <ErrorBoundary fallback={({ error, reset }) => (
 *     <div>
 *       <p>{error?.message}</p>
 *       <button onClick={reset}>Reintentar</button>
 *     </div>
 *   )}>
 *     <VaultView />
 *   </ErrorBoundary>
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: { componentStack: string }) {
    // Best-effort log — el logger del servidor no está disponible en
    // client components, así que usamos console.error con redacción.
    console.error("[ErrorBoundary]", {
      message: error.message,
      stack: error.stack?.split("\n").slice(0, 3).join(" | "),
      componentStack: info.componentStack?.split("\n").slice(0, 3).join(" | "),
    });
  }

  reset = () => {
    this.setState({ hasError: false, error: undefined });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback({ error: this.state.error, reset: this.reset });
      }
      return (
        <div className="flex min-h-screen flex-col items-center justify-center gap-4 px-4 text-center">
          <h1 className="text-2xl font-bold">Algo salió mal</h1>
          <p className="text-sm text-muted-foreground">{this.state.error?.message}</p>
          <button
            type="button"
            onClick={this.reset}
            className="rounded-md border border-border bg-background px-4 py-2 text-sm hover:bg-accent"
          >
            Reintentar
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

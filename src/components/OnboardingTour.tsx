"use client";

import { useState } from "react";

interface Step {
  title: string;
  description: string;
  target?: string;
}

const steps: Step[] = [
  {
    title: "¡Bienvenido a Zero-Knowledge Vault!",
    description:
      "Tus secretos están cifrados de extremo a extremo. Nadie más que tú puede leerlos.",
  },
  {
    title: "Crear un secreto",
    description: "Usa el botón 'Nuevo secreto' para guardar tu primera contraseña o nota.",
    target: "[data-testid='new-secret-btn']",
  },
  {
    title: "Compartir de forma segura",
    description: "Comparte secretos con tu equipo. El cifrado extremo a extremo se mantiene.",
    target: "[data-testid='share-btn']",
  },
  {
    title: "Gestionar tu cuenta",
    description: "En Ajustes puedes rotar tu contraseña maestra, ver dispositivos y más.",
    target: "[data-testid='settings-link']",
  },
];

export function OnboardingTour() {
  const [isActive, setIsActive] = useState(() => {
    if (typeof window !== "undefined") {
      return !localStorage.getItem("zk-vault-onboarding-done");
    }
    return false;
  });
  const [currentStep, setCurrentStep] = useState(0);

  if (!isActive) return null;

  const step = steps[currentStep];
  const isLast = currentStep === steps.length - 1;

  const handleNext = () => {
    if (isLast) {
      localStorage.setItem("zk-vault-onboarding-done", "true");
      setIsActive(false);
    } else {
      setCurrentStep((prev) => prev + 1);
    }
  };

  const handleSkip = () => {
    localStorage.setItem("zk-vault-onboarding-done", "true");
    setIsActive(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30">
      <div className="bg-card text-card-foreground rounded-lg shadow-xl border max-w-md w-full mx-4 p-6">
        <div className="flex items-center justify-between mb-4">
          <span className="text-xs text-muted-foreground">
            {currentStep + 1} / {steps.length}
          </span>
          <button
            onClick={handleSkip}
            className="text-xs text-muted-foreground hover:text-foreground"
          >
            Saltar
          </button>
        </div>
        <h3 className="text-lg font-semibold mb-2">{step.title}</h3>
        <p className="text-sm text-muted-foreground mb-6">{step.description}</p>
        <div className="flex justify-end gap-2">
          <button
            onClick={handleSkip}
            className="px-4 py-2 text-sm rounded-md border hover:bg-accent"
          >
            Saltar tutorial
          </button>
          <button
            onClick={handleNext}
            className="px-4 py-2 text-sm rounded-md bg-primary text-primary-foreground hover:bg-primary/90"
          >
            {isLast ? "¡Listo!" : "Siguiente"}
          </button>
        </div>
      </div>
    </div>
  );
}

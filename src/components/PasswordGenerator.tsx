"use client";

import { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { RefreshCw, Copy, Check } from "lucide-react";

interface PasswordGeneratorProps {
  onGenerate?: (password: string) => void;
}

const CHARSETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numbers: "0123456789",
  symbols: "!@#$%^&*()_+-=[]{}|;:,.<>?",
};

/**
 * Generador de contraseñas criptográficamente seguro.
 *
 */
export function PasswordGenerator({ onGenerate }: PasswordGeneratorProps) {
  const { toast } = useToast();
  const [length, setLength] = useState(24);
  const [useLower, setUseLower] = useState(true);
  const [useUpper, setUseUpper] = useState(true);
  const [useNumbers, setUseNumbers] = useState(true);
  const [useSymbols, setUseSymbols] = useState(true);
  const [generated, setGenerated] = useState("");
  const [copied, setCopied] = useState(false);

  const generate = useCallback(() => {
    let charset = "";
    if (useLower) charset += CHARSETS.lower;
    if (useUpper) charset += CHARSETS.upper;
    if (useNumbers) charset += CHARSETS.numbers;
    if (useSymbols) charset += CHARSETS.symbols;
    if (!charset) charset = CHARSETS.lower;

    const array = new Uint32Array(length);
    crypto.getRandomValues(array);

    let result = "";
    for (let i = 0; i < length; i++) {
      result += charset[array[i] % charset.length];
    }
    setGenerated(result);
    onGenerate?.(result);
  }, [length, useLower, useUpper, useNumbers, useSymbols, onGenerate]);

  const copy = () => {
    if (!generated) return;
    navigator.clipboard.writeText(generated);
    setCopied(true);
    toast({ title: "Contraseña copiada" });
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-2 rounded-md border border-border/60 bg-background/60 p-3">
      <div className="flex items-center justify-between">
        <Label className="text-xs text-muted-foreground">Generador de contraseñas</Label>
        <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-[10px]" onClick={generate}>
          <RefreshCw className="mr-1 size-3" /> Generar
        </Button>
      </div>
      {generated ? (
        <div className="flex items-center gap-2">
          <code className="flex-1 truncate rounded bg-muted/40 px-2 py-1.5 font-mono text-[11px]">
            {generated}
          </code>
          <Button type="button" variant="ghost" size="sm" className="h-7 px-2" onClick={copy}>
            {copied ? <Check className="size-3" /> : <Copy className="size-3" />}
          </Button>
        </div>
      ) : null}
      <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={useLower} onChange={(e) => setUseLower(e.target.checked)} className="size-3" />
          a-z
        </label>
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={useUpper} onChange={(e) => setUseUpper(e.target.checked)} className="size-3" />
          A-Z
        </label>
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={useNumbers} onChange={(e) => setUseNumbers(e.target.checked)} className="size-3" />
          0-9
        </label>
        <label className="flex items-center gap-1">
          <input type="checkbox" checked={useSymbols} onChange={(e) => setUseSymbols(e.target.checked)} className="size-3" />
          !@#
        </label>
        <label className="flex items-center gap-1 ml-auto">
          Len:
          <input
            type="range"
            min="8"
            max="48"
            value={length}
            onChange={(e) => setLength(Number(e.target.value))}
            className="w-16"
          />
          <span className="w-6 font-mono">{length}</span>
        </label>
      </div>
    </div>
  );
}

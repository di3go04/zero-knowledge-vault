import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import { api, getSessionToken, clearSession, setSessionToken } from "./api-client";

interface Session {
  userId: string;
  token: string;
}

interface AuthContextType {
  session: Session | null;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  session: null,
  isLoading: true,
  login: async () => {},
  logout: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    getSessionToken().then((token) => {
      if (token) setSession({ userId: "", token });
      setIsLoading(false);
    });
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const result = await api.login(email, password);
    await setSessionToken(result.token);
    setSession({ userId: result.userId, token: result.token });
  }, []);

  const logout = useCallback(async () => {
    await clearSession();
    setSession(null);
  }, []);

  return (
    <AuthContext.Provider value={{ session, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);

"use client";

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from "react";

interface AuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => boolean;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// Credentials (in production, use environment variables or backend auth)
const VALID_USERNAME = "qwertyhq";
const VALID_PASSWORD = "e237237!";

// Session storage key
const AUTH_KEY = "xray_auth_session";
const SESSION_DURATION = 24 * 60 * 60 * 1000; // 24 hours

interface Session {
  authenticated: boolean;
  expiresAt: number;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Check session on mount
  useEffect(() => {
    const checkSession = () => {
      try {
        const stored = localStorage.getItem(AUTH_KEY);
        if (stored) {
          const session: Session = JSON.parse(stored);
          if (session.authenticated && session.expiresAt > Date.now()) {
            setIsAuthenticated(true);
          } else {
            localStorage.removeItem(AUTH_KEY);
          }
        }
      } catch {
        localStorage.removeItem(AUTH_KEY);
      }
      setIsLoading(false);
    };

    checkSession();
  }, []);

  const login = useCallback((username: string, password: string): boolean => {
    if (username === VALID_USERNAME && password === VALID_PASSWORD) {
      const session: Session = {
        authenticated: true,
        expiresAt: Date.now() + SESSION_DURATION,
      };
      localStorage.setItem(AUTH_KEY, JSON.stringify(session));
      setIsAuthenticated(true);
      return true;
    }
    return false;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem(AUTH_KEY);
    setIsAuthenticated(false);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

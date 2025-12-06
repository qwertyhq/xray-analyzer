import { Stats, NodeStats, UserStats } from './types';

// Server-side: call Go backend directly
// Client-side: use relative URL (Caddy routes /api/* to Go)
const API_BASE = typeof window === 'undefined' 
  ? 'http://localhost:8237'  // Server-side
  : '';  // Client-side (browser)

async function fetchAPI<T>(endpoint: string): Promise<T> {
  const res = await fetch(`${API_BASE}${endpoint}`, {
    cache: 'no-store',
    headers: {
      'Content-Type': 'application/json',
    },
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status}`);
  }
  return res.json();
}

export async function getStats(): Promise<Stats> {
  return fetchAPI<Stats>('/api/stats');
}

export async function getNodes(): Promise<NodeStats[]> {
  return fetchAPI<NodeStats[]>('/api/nodes');
}

export async function getUsers(): Promise<UserStats[]> {
  return fetchAPI<UserStats[]>('/api/users');
}

export async function getAllUsers(): Promise<UserStats[]> {
  return fetchAPI<UserStats[]>('/api/users/all');
}

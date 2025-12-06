import { Stats, NodeStats, UserStats } from './types';

// API calls go through Next.js rewrites to Go backend
const API_BASE = '';

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

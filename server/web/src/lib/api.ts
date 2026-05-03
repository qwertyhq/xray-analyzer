import { Stats, NodeStats, UserStats } from './types';

// Server-side uses internal URL (localhost in same container), client uses relative path
const API_BASE = process.env.INTERNAL_API_URL || 'http://localhost:8237';

async function fetchAPI<T>(endpoint: string): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const res = await fetch(url, {
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

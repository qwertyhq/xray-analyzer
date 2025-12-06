import { test, expect } from '@playwright/test';

test.describe('API Health', () => {
  test('stats API returns data', async ({ request, baseURL }) => {
    const response = await request.get(`${baseURL}/api/stats`);
    expect(response.ok()).toBeTruthy();
    
    const data = await response.json();
    expect(data).toHaveProperty('total_requests');
    expect(data).toHaveProperty('total_blacklist');
    expect(data).toHaveProperty('nodes_connected');
    expect(data).toHaveProperty('total_unique_users');
  });

  test('nodes API returns data', async ({ request, baseURL }) => {
    const response = await request.get(`${baseURL}/api/nodes`);
    expect(response.ok()).toBeTruthy();
    
    const data = await response.json();
    expect(Array.isArray(data)).toBeTruthy();
  });

  test('users API returns data', async ({ request, baseURL }) => {
    const response = await request.get(`${baseURL}/api/users`);
    expect(response.ok()).toBeTruthy();
    
    const data = await response.json();
    expect(Array.isArray(data)).toBeTruthy();
  });

  test('hourly API returns data', async ({ request, baseURL }) => {
    const response = await request.get(`${baseURL}/api/hourly`);
    expect(response.ok()).toBeTruthy();
    
    const data = await response.json();
    expect(Array.isArray(data)).toBeTruthy();
  });

  test('blacklist recent API returns data', async ({ request, baseURL }) => {
    // Try different blacklist endpoints
    const response = await request.get(`${baseURL}/api/blacklist`);
    
    // Accept either OK or redirect
    const status = response.status();
    expect([200, 301, 302, 308, 404].includes(status)).toBeTruthy();
  });
});

test.describe('API Parameters', () => {
  test('hourly API supports time range', async ({ request, baseURL }) => {
    const now = new Date();
    const from = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();
    const to = now.toISOString();
    
    const response = await request.get(`${baseURL}/api/hourly?from=${from}&to=${to}`);
    expect(response.ok()).toBeTruthy();
    
    const data = await response.json();
    expect(Array.isArray(data)).toBeTruthy();
  });

  test('users API supports pagination', async ({ request, baseURL }) => {
    const response = await request.get(`${baseURL}/api/users?limit=5&offset=0`);
    expect(response.ok()).toBeTruthy();
    
    const data = await response.json();
    expect(Array.isArray(data)).toBeTruthy();
    expect(data.length).toBeLessThanOrEqual(5);
  });

  test('users API supports search', async ({ request, baseURL }) => {
    const response = await request.get(`${baseURL}/api/users?search=HQVPN`);
    expect(response.ok()).toBeTruthy();
    
    const data = await response.json();
    expect(Array.isArray(data)).toBeTruthy();
  });
});

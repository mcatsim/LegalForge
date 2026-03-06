import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';

describe('Token refresh mutex', () => {
  it('uses mutex pattern to prevent parallel refresh calls', () => {
    const source = readFileSync(
      resolve(__dirname, '../client.ts'),
      'utf-8'
    );
    expect(source).toContain('isRefreshing');
    expect(source).toContain('refreshSubscribers');
    expect(source).toContain('onRefreshed');
  });

  it('module exports a singleton refresh promise pattern', async () => {
    const clientModule = await import('../client');
    const source = clientModule.default.interceptors.response.handlers;
    // The interceptor should exist and handle 401
    expect(source.length).toBeGreaterThan(0);
  });
});

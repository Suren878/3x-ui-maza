import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpError, httpRequest } from '@/api/http-init';
import { createMazaClient } from '@/pages/maza/createClient';

vi.mock('@/api/http-init', async importOriginal => ({
  ...await importOriginal<typeof import('@/api/http-init')>(), httpRequest: vi.fn(),
}));
const request = vi.mocked(httpRequest);
const response = (data: unknown) => ({ ok: true, status: 200, statusText: 'OK', data });
const status = (pending: boolean) => response({ success: true, obj: {
  pending, clients: [{ name: 'Mac', email: 'mac' }],
} });
const postCount = () => request.mock.calls.filter(([method]) => method === 'POST').length;

beforeEach(() => { request.mockReset(); vi.useFakeTimers(); });
afterEach(() => vi.useRealTimers());

describe('MAZA creation while the administrator uses the VPN', () => {
  it('recovers a lost POST response without creating a duplicate', async () => {
    request.mockRejectedValueOnce(new TypeError('Load failed'))
      .mockRejectedValueOnce(new TypeError('Load failed'))
      .mockResolvedValueOnce(status(true)).mockResolvedValueOnce(status(false));
    const result = createMazaClient('Mac', 'mac');
    await vi.runAllTimersAsync();
    expect(await result).toEqual({ success: true });
    expect(postCount()).toBe(1);
  });

  it('waits for an accepted client to become usable', async () => {
    request.mockResolvedValueOnce(response({ success: true, obj: { pending: true } }))
      .mockResolvedValueOnce(status(true)).mockResolvedValueOnce(status(false));
    const result = createMazaClient('Mac', 'mac');
    await vi.runAllTimersAsync();
    expect(await result).toEqual({ success: true });
    expect(postCount()).toBe(1);
  });

  it('keeps a saved but unapplied client distinct from a failed creation', async () => {
    request.mockResolvedValueOnce(response({ success: true })).mockResolvedValue(status(true));
    const result = createMazaClient('Mac', 'mac');
    await vi.runAllTimersAsync();
    expect(await result).toMatchObject({ success: true, pending: true });
    expect(postCount()).toBe(1);
  });

  it('preserves a real duplicate-name error without treating an old client as new', async () => {
    request.mockResolvedValueOnce(response({ success: false, msg: 'client name already exists' }));
    expect(await createMazaClient('Mac', 'mac')).toEqual({ success: false, msg: 'client name already exists' });
    expect(request).toHaveBeenCalledTimes(1);
  });

  it('does not recover permission failures as success', async () => {
    request.mockRejectedValueOnce(new HttpError(403, 'Forbidden', { msg: 'Access denied' }));
    expect(await createMazaClient('Mac', 'mac')).toEqual({ success: false, msg: 'Access denied' });
    expect(request).toHaveBeenCalledTimes(1);
  });

  it('reports an unknown outcome when the connection never returns', async () => {
    request.mockRejectedValue(new TypeError('Load failed'));
    const result = createMazaClient('Mac', 'mac');
    await vi.runAllTimersAsync();
    expect(await result).toMatchObject({ success: false });
    expect((await result).msg).toContain('Обновите список');
    expect(postCount()).toBe(1);
  });
});

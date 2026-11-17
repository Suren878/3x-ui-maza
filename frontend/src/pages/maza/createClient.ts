import { HttpError, httpRequest } from '@/api/http-init';

type Status = { pending: boolean; clients: { name: string; email: string }[] };
type Envelope<T = unknown> = { success: boolean; msg?: string; obj?: T };
export type CreationResult = { success: boolean; pending?: boolean; msg?: string };
const clientsURL = '/panel/maza/api/clients';

// Never repeat the POST after a broken VPN connection: creation may already
// have been committed. Only read status until the saved client becomes usable.
export async function createMazaClient(name: string, email?: string): Promise<CreationResult> {
  let saved = false;
  try {
    const response = await httpRequest('POST', clientsURL, { name, email }, {
      headers: { 'Content-Type': 'application/json' }, timeout: 10000,
    });
    const result = response.data as Envelope;
    if (!result.success) return { success: false, msg: result.msg || 'Не удалось создать клиента MAZA.' };
    saved = true;
  } catch (error) {
    if (error instanceof HttpError && error.status < 500) {
      const result = error.response.data as Envelope | null;
      return { success: false, msg: result?.msg || 'Запрос создания отклонён сервером.' };
    }
  }
  for (let attempt = 0; attempt < 12; attempt++) {
    if (attempt > 0) await new Promise(resolve => setTimeout(resolve, 1000));
    try {
      const response = await httpRequest('GET', clientsURL, undefined, { timeout: 1500 });
      const result = response.data as Envelope<Status>;
      if (!result.success || !result.obj) continue;
      const found = result.obj.clients.some(c => email ? c.email === email : c.name === name);
      if (found) {
        saved = true;
        if (!result.obj.pending) return { success: true };
      }
    } catch { /* The core may be reconnecting the administrator's VPN. */ }
  }
  return saved
    ? { success: true, pending: true, msg: 'Клиент сохранён. Настройки ещё применяются; QR появится после завершения.' }
    : { success: false, msg: 'Связь с панелью прервалась. Обновите список клиентов перед повторным созданием.' };
}

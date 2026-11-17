import { useEffect, useState } from 'react';
import { HttpUtil } from '@/utils';
import type { ClientRecord, InboundOption } from '@/hooks/useClients';

type Profile = { id: string; link: string };

export function useMazaProfile(open: boolean, client: ClientRecord | null, inboundsById: Record<number, InboundOption>) {
  const [result, setResult] = useState<{ email: string; profile: Profile | null }>({ email: '', profile: null });
  const attached = !!client?.inboundIds?.some((id) => inboundsById[id]?.tag === 'maza-managed');
  const email = open && attached ? client?.email || '' : '';
  useEffect(() => {
    if (!email) return;
    let active = true;
    void HttpUtil.get<Profile>(`/panel/maza/api/by-email/${encodeURIComponent(email)}/share`, undefined, { silent: true }).then((msg) => {
      if (active) setResult({ email, profile: msg.success ? (msg.obj ?? null) : null });
    });
    return () => { active = false; };
  }, [email]);
  return { attached, profile: email && result.email === email ? result.profile : null };
}

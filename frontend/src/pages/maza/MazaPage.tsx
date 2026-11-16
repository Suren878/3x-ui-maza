import { useEffect, useState } from 'react';
import { Alert, Button, Card, Input, Modal, Popconfirm, QRCode, Space, Table, Tag, Typography } from 'antd';
import { HttpUtil } from '@/utils';

type Client = { id: string; name: string; address: string; created: number };
type Status = { clients: Client[]; origin: string; pending: boolean; limit: number };
const api = '/panel/maza/api';

export default function MazaPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [share, setShare] = useState<{ name: string; link: string } | null>(null);
  const [error, setError] = useState('');
  async function refresh() {
    const result = await HttpUtil.get<Status>(`${api}/clients`, undefined, { silent: true });
    if (result.success && result.obj) { setStatus(result.obj); setError(''); }
    else setError(result.msg || 'MAZA недоступен');
  }
  useEffect(() => { void refresh(); const timer = setInterval(() => void refresh(), 5000); return () => clearInterval(timer); }, []);
  async function create() {
    setBusy(true);
    try { const r = await HttpUtil.post(`${api}/clients`, { name }, { headers: { 'Content-Type': 'application/json' } }); if (r.success) setName(''); await refresh(); }
    finally { setBusy(false); }
  }
  async function remove(id: string) {
    setBusy(true);
    try { await HttpUtil.post(`${api}/clients/${id}/delete`); await refresh(); }
    finally { setBusy(false); }
  }
  async function showQR(c: Client) {
    const r = await HttpUtil.get<{ link: string }>(`${api}/clients/${c.id}/share`);
    if (r.success && r.obj) setShare({ name: c.name, link: r.obj.link });
  }
  const base = (window.X_UI_BASE_PATH || '/').replace(/\/$/, '');
  return <Space orientation="vertical" size="large" style={{ width: '100%' }}>
    <div><Typography.Title level={2}>MAZA</Typography.Title><Typography.Text type="secondary">Корпоративные подключения через HTTPS · MAZA 0.1</Typography.Text></div>
    {error && <Alert type="error" title={error} showIcon />}
    <Alert type="info" showIcon title="Профиль MAZA" description="QR предназначен для клиента с поддержкой MAZA. Для текущего прототипа скачайте ZIP с настройками MAZA и WireGuard. При изменении клиентов MAZA кратко переподключается. Подключение этого формата к AIRClient находится на следующем этапе." />
    <Card title="Новый клиент" extra={<Tag color={status?.pending ? 'orange' : 'blue'}>{status?.pending ? 'Применяем изменения' : status?.origin || 'Подключение к серверу'}</Tag>}>
      <Space wrap><Input aria-label="Имя клиента" placeholder="Например, рабочий Mac" value={name} onChange={e => setName(e.target.value)} maxLength={64} onPressEnter={() => { if (name.trim() && !busy && !status?.pending) void create(); }} style={{ width: 280 }} />
      <Button type="primary" loading={busy} disabled={!name.trim() || !status || status.pending || status.clients.length >= status.limit} onClick={() => void create()}>Создать клиента</Button>
      <Typography.Text type="secondary">{status?.clients.length || 0} / {status?.limit || 64}</Typography.Text></Space>
    </Card>
    <Card title="Клиенты MAZA">
      <Table<Client> rowKey="id" dataSource={status?.clients || []} pagination={{ pageSize: 10 }} scroll={{ x: 620 }} columns={[
        { title: 'Имя', dataIndex: 'name' },
        { title: 'Адрес', dataIndex: 'address' },
        { title: 'Создан', dataIndex: 'created', render: (v: number) => new Date(v * 1000).toLocaleDateString() },
        { title: 'Доступ', render: (_, c) => <Space>
          <Button disabled={status?.pending} onClick={() => void showQR(c)}>QR</Button>
          <Button disabled={status?.pending} href={`${base}/panel/maza/api/clients/${c.id}/bundle`}>ZIP</Button>
          <Popconfirm title={`Удалить доступ «${c.name}»?`} description="Ключи и действующие MAZA-сессии будут отозваны." onConfirm={() => remove(c.id)} okText="Удалить" cancelText="Отмена"><Button danger disabled={busy}>Удалить</Button></Popconfirm>
        </Space> },
      ]} />
    </Card>
    <Modal title={share?.name} open={!!share} onCancel={() => setShare(null)} footer={null} destroyOnHidden>
      {share && <Space orientation="vertical" style={{ width: '100%', alignItems: 'center' }}>
        <QRCode value={share.link} size={360} errorLevel="L" />
        <Typography.Text type="secondary">QR даёт доступ к сети. Передавайте его только владельцу устройства.</Typography.Text>
        <Button onClick={() => void navigator.clipboard.writeText(share.link)}>Скопировать профиль MAZA</Button>
      </Space>}
    </Modal>
  </Space>;
}

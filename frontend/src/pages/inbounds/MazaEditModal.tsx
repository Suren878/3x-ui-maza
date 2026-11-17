import { useEffect, useState } from 'react';
import { Alert, Button, Form, Input, Modal } from 'antd';
import { HttpUtil } from '@/utils';
import type { DBInbound } from '@/models/dbinbound';

export default function MazaEditModal({ record, onClose, onSaved }: {
  record: DBInbound | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [remark, setRemark] = useState('');
  const [origin, setOrigin] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!record) return;
    let active = true;
    setRemark(record.remark || 'MAZA');
    setOrigin('');
    void HttpUtil.get<{ origin: string; remark: string }>('/panel/maza/api/clients', undefined, { silent: true }).then((result) => {
      if (active && result.success && result.obj) {
        setOrigin(result.obj.origin);
        if (result.obj.remark) setRemark(result.obj.remark);
      }
    });
    return () => { active = false; };
  }, [record]);
  async function save() {
    if (!remark.trim() || busy) return;
    setBusy(true);
    try {
      const result = await HttpUtil.post('/panel/maza/api/settings', { remark: remark.trim() }, { headers: { 'Content-Type': 'application/json' } });
      if (result.success) { onSaved(); onClose(); }
    } finally { setBusy(false); }
  }
  let port = '—';
  try { if (origin) port = new URL(origin).port || '9443'; } catch { /* Invalid server origin. */ }
  const base = (window.X_UI_BASE_PATH || '/').replace(/\/$/, '');
  return <Modal open={!!record} title="Изменить MAZA" okText="Сохранить" cancelText="Отмена" confirmLoading={busy} onOk={save} onCancel={onClose} destroyOnHidden>
    <Form layout="vertical">
      <Form.Item label="Название"><Input value={remark} maxLength={64} onChange={(e) => setRemark(e.target.value)} /></Form.Item>
      <Form.Item label="Адрес сервера"><Input value={origin} readOnly /></Form.Item>
      <Form.Item label="Внешний порт"><Input value={port} readOnly /></Form.Item>
      <Alert type="info" showIcon title="Адрес и порт настроены на сервере" description="Для изменения адреса или порта обновите настройки MAZA на сервере и повторно выдайте профили клиентам." />
      <Button href={`${base}/panel/maza`} style={{ marginTop: 16 }}>Управление клиентами MAZA</Button>
    </Form>
  </Modal>;
}

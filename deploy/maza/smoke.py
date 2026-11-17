#!/usr/bin/env python3
"""Operator-only local API check. Secrets stay in memory or explicit mode-0600 outputs."""
import argparse,base64,http.cookiejar,io,json,os,subprocess,time,urllib.request,urllib.error,zipfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('mode',choices=['smoke','create','delete','disable','enable']);p.add_argument('--url',required=True);p.add_argument('--credentials',required=True);p.add_argument('--output',required=True);p.add_argument('--tools',required=True);a=p.parse_args()
os.umask(0o077)
root=Path(a.output);root.mkdir(parents=True,exist_ok=True);root.chmod(0o700)
base=a.url.rstrip('/')
jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar));token=''
def req(path,data=None,auth=True,csrf=True):
 headers={'X-Requested-With':'XMLHttpRequest'}
 if csrf and token:headers['X-CSRF-Token']=token
 if data is not None:headers['Content-Type']='application/json'
 request=urllib.request.Request(base+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
 try:response=opener.open(request,timeout=30)
 except urllib.error.HTTPError as e:response=e
 with response:return response.status,response.headers,response.read()

def api(path,data=None):
 code,h,b=req(path,data);v=json.loads(b)
 if code!=200 or not v.get('success'):raise RuntimeError('API failed '+path+': '+str(v.get('msg',code)))
 return v.get('obj')
route='/panel/maza/api/clients'
token=api('/csrf-token')
api('/login',json.loads(Path(a.credentials).read_text()))
token=api('/csrf-token')
for _ in range(40):
 status=api(route)
 if not status['pending']:break
 time.sleep(.5)
else:raise RuntimeError('native backend remains pending')
def delete(c):api(route+'/'+c['id']+'/delete',{})
def export(c):
 code,h,b=req(route+'/'+c['id']+'/share');assert code==200 and h['Cache-Control']=='no-store'
 link=json.loads(b)['obj']['link'];v=link.removeprefix('maza://');profile=json.loads(base64.urlsafe_b64decode(v+'='*(-len(v)%4)))
 assert profile['version']==2 and len(profile['maza'])==21 and profile['wireguard']['mtu']==1280
 assert 'origin' not in profile and 'auth_private_key' not in profile
 (root/'profile.json').write_text(json.dumps(profile));(root/'profile.maza').write_text(link);(root/'client.json').write_text(json.dumps(c))
 code,h,b=req(route+'/'+c['id']+'/bundle');assert code==200 and h['Cache-Control']=='no-store'
 with zipfile.ZipFile(io.BytesIO(b)) as z:
  assert set(z.namelist())=={'profile.json','profile.maza','README.txt'}
  assert all((i.external_attr>>16)&0o777==0o600 for i in z.infolist())
 print('PASS: private v2 link, QR payload and ZIP')
def probe(ok):
 result=subprocess.run([a.tools+'/probe',str(root/'profile.json'),'127.0.0.1:9443'],capture_output=True,timeout=15)
 assert (result.returncode==0)==ok, 'native peer acceptance/revocation mismatch: '+result.stderr.decode()[:200]
 print('PASS: native handshake '+('accepted' if ok else 'rejected'))
if a.mode=='create':
 assert not any(c['name']=='MAZA native deployment check' for c in status['clients'])
 api(route,{'name':'MAZA native deployment check'}); c=next(c for c in api(route)['clients'] if c['name']=='MAZA native deployment check');export(c)
elif a.mode in ['delete','disable','enable']:
 c=json.loads((root/'client.json').read_text())
 if a.mode=='delete':delete(c)
 else:api(route+'/'+c['id']+'/enable',{'enabled':a.mode=='enable'})
 print('PASS: temporary client '+a.mode)
else:
 assert not status['clients'], 'isolated smoke requires empty managed state'
 # Clean only orphan records left by an earlier run of this isolated fixture.
 for email in ['maza-smoke-a','maza-smoke-b']:
  code,_,raw=req('/panel/api/clients/get/'+email);old=json.loads(raw)
  if old.get('success'):
   assert not old['obj']['inboundIds'], 'test identity still attached elsewhere'
   api('/panel/api/clients/del/'+email,{})
 # Use a fresh anonymous opener to avoid reusing the operator cookie jar.
 anon=urllib.request.Request(base+route,headers={'X-Requested-With':'XMLHttpRequest'})
 try: urllib.request.urlopen(anon);raise RuntimeError('anonymous access accepted')
 except urllib.error.HTTPError as e:assert e.code==401
 assert req(route,{'name':'csrf-probe'},csrf=False)[0]==403
 try:
  api(route,{'name':'Smoke A','email':'maza-smoke-a'});api(route,{'name':'Smoke B','email':'maza-smoke-b'})
  clients=api(route)['clients'];assert len(clients)==2 and clients[0]['address']!=clients[1]['address']
  assert all(set(c)=={'id','name','email','address','created','enabled'} for c in clients)
  c=next(c for c in clients if c['name']=='Smoke A');export(c);probe(True)
  for path,body in [('/panel/api/clients/update/'+c['email'],{'enable':False}),('/panel/api/clients/del/'+c['email'],{})]:
   code,_,raw=req(path,body);assert code==200 and not json.loads(raw)['success'], 'generic mutation bypassed managed state'
  assert len(api(route)['clients'])==2
  api(route+'/'+c['id']+'/enable',{'enabled':False});probe(False)
  api(route+'/'+c['id']+'/enable',{'enabled':True});probe(True)
  delete(c);probe(False)
  api(route,{'name':'Smoke A','email':'maza-smoke-a'})
  print('PASS: revoked client name can be reused')
 finally:
  for c in api(route)['clients']:
   if c['name'] in ['Smoke A','Smoke B']:delete(c)
 assert not api(route)['clients'];print('PASS: isolated API, CSRF, provision, disable, enable, revoke and cleanup')

#!/usr/bin/env python3
from __future__ import annotations
import base64, hashlib, json, os, re, socket, ssl, subprocess, tempfile, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/'output'
XRAY=Path(os.environ.get('XRAY_BIN','/opt/hostedtoolcache/xray/xray'))
LIMIT=int(os.environ.get('REAL_DELAY_CANDIDATES','3200')); WORKERS=int(os.environ.get('REAL_DELAY_WORKERS','32'))
TIMEOUT=float(os.environ.get('REAL_DELAY_NODE_TIMEOUT','6')); BASE=int(os.environ.get('REAL_DELAY_SOCKS_BASE','21000'))
TEST_HOST=os.environ.get('REAL_DELAY_TEST_HOST','www.gstatic.com'); TEST_PATH=os.environ.get('REAL_DELAY_TEST_PATH','/generate_204')
ALIASES={'uk':'GB','usa':'US','america':'US','uae':'AE','emirates':'AE','singapore':'SG','seychelles':'SC','slovenia':'SI','germany':'DE','france':'FR','canada':'CA','australia':'AU','netherlands':'NL','poland':'PL','turkey':'TR','turkiye':'TR','hongkong':'HK','finland':'FI','sweden':'SE','denmark':'DK','bulgaria':'BG','china':'CN','estonia':'EE','czechia':'CZ','southafrica':'ZA','newzealand':'NZ','saudiarabia':'SA'}

def b64d(s): return base64.urlsafe_b64decode(s+'='*((-len(s))%4))
def q(uri): return parse_qs(urlparse(uri).query,keep_blank_values=True)
def first(d,*ks,default=''):
    for k in ks:
        if d.get(k): return unquote(d[k][0])
    return default
def proto(uri):
    s=uri.split(':',1)[0].lower(); return 'shadowsocks' if s=='ss' else s

def country_from_uri(uri,fallback='UNKNOWN'):
    frag=unquote(urlparse(uri).fragment or ''); compact=re.sub(r'[^a-z0-9]+','',frag.lower())
    for k,v in ALIASES.items():
        if k in compact: return v
    m=re.search(r'(?<![A-Za-z0-9])([A-Z]{2})(?![A-Za-z0-9])',frag)
    return m.group(1).upper() if m else fallback

def load_pool():
    rows={}
    for kind in ('countries','protocols'):
        for p in sorted((OUT/kind).glob('*.txt')):
            c=p.stem.upper() if kind=='countries' else None
            for line in p.read_text(encoding='utf-8',errors='replace').splitlines():
                u=line.strip()
                if not re.match(r'^(vless|vmess|trojan|ss)://',u,re.I): continue
                rows.setdefault(hashlib.sha1(u.encode()).hexdigest(),{'uri':u,'country':c or country_from_uri(u),'protocol':proto(u)})
    return list(rows.values())

def choose(pool):
    by={}
    for r in pool: by.setdefault(r['country'],[]).append(r)
    countries=sorted(by)
    total=sum(map(len,by.values()))
    if not total: return []
    quotas={c:max(1,int(LIMIT*len(by[c])/total)) for c in countries}
    while sum(quotas.values())>min(LIMIT,total):
        c=max(quotas,key=lambda x:quotas[x])
        if quotas[c]<=1: break
        quotas[c]-=1
    while sum(quotas.values())<min(LIMIT,total):
        c=max(countries,key=lambda x:len(by[x])-quotas[x])
        if quotas[c]>=len(by[c]): break
        quotas[c]+=1
    out=[]
    for c in countries:
        items=by[c]; n=min(quotas[c],len(items))
        idxs=sorted({min(len(items)-1,int(i*len(items)/n)) for i in range(n)})
        if 0 not in idxs: idxs[0]=0
        out.extend(items[i] for i in idxs[:n])
    return out[:LIMIT]

def vless(uri):
    p=urlparse(uri); z=q(uri); u=p.username or ''
    user={'id':unquote(u),'encryption':first(z,'encryption',default='none')}; flow=first(z,'flow')
    if flow: user['flow']=flow
    o={'protocol':'vless','settings':{'vnext':[{'address':p.hostname,'port':p.port,'users':[user]}]}}
    net=first(z,'type',default='tcp'); sec=first(z,'security',default='none'); st={'network':net,'security':sec}
    if net=='ws': st['wsSettings']={'path':first(z,'path',default='/'),'headers':({'Host':first(z,'host')} if first(z,'host') else {})}
    elif net=='grpc': st['grpcSettings']={'serviceName':first(z,'serviceName'),'authority':first(z,'authority')}
    elif net=='xhttp': st['xhttpSettings']={'path':first(z,'path',default='/'),'mode':first(z,'mode',default='auto'),'host':first(z,'host')}
    if sec=='tls':
        t={'serverName':first(z,'sni','serverName',default=p.hostname)}; fp=first(z,'fp'); alpn=first(z,'alpn')
        if fp:t['fingerprint']=fp
        if alpn:t['alpn']=[x for x in alpn.split(',') if x]
        st['tlsSettings']=t
    elif sec=='reality':
        st['realitySettings']={'serverName':first(z,'sni','serverName',default=p.hostname),'fingerprint':first(z,'fp',default='chrome'),'publicKey':first(z,'pbk'),'shortId':first(z,'sid'),'spiderX':first(z,'spx',default='/')}
    o['streamSettings']=st; return o

def vmess(uri):
    raw=uri.split('vmess://',1)[1].split('#',1)[0]; obj=None
    try: obj=json.loads(b64d(raw).decode())
    except Exception: pass
    if obj is None:
        p=urlparse(uri); z=q(uri); obj={'add':p.hostname,'port':p.port,'id':p.username or '','net':first(z,'type',default='tcp'),'host':first(z,'host'),'path':first(z,'path',default='/'),'tls':first(z,'security')}
    net=obj.get('net') or 'tcp'; tls=bool(obj.get('tls'))
    st={'network':net,'security':'tls' if tls else 'none'}
    if net=='ws': st['wsSettings']={'path':obj.get('path') or '/','headers':{'Host':obj.get('host') or ''}}
    if tls: st['tlsSettings']={'serverName':obj.get('sni') or obj.get('host') or obj.get('add')}
    return {'protocol':'vmess','settings':{'vnext':[{'address':obj.get('add'),'port':int(obj.get('port')),'users':[{'id':obj.get('id'),'alterId':int(obj.get('aid',0) or 0),'security':obj.get('scy','auto')}]}]},'streamSettings':st}

def trojan(uri):
    p=urlparse(uri); z=q(uri); st={'network':first(z,'type',default='tcp'),'security':first(z,'security',default='tls')}
    if st['network']=='ws': st['wsSettings']={'path':first(z,'path',default='/'),'headers':{'Host':first(z,'host',default='')}}
    if st['security']=='tls': st['tlsSettings']={'serverName':first(z,'sni',default=p.hostname)}
    return {'protocol':'trojan','settings':{'servers':[{'address':p.hostname,'port':p.port,'password':unquote(p.username or '')}]},'streamSettings':st}

def ss(uri):
    raw=uri.split('ss://',1)[1].split('#',1)[0]
    if '@' in raw:
        ui,hp=raw.rsplit('@',1)
        try: ui=b64d(ui).decode()
        except Exception: ui=unquote(ui)
    else:
        dec=b64d(raw).decode(); ui,hp=dec.rsplit('@',1)
    method,pw=ui.split(':',1); host,port=hp.rsplit(':',1)
    return {'protocol':'shadowsocks','settings':{'servers':[{'address':host,'port':int(port),'method':method,'password':pw}]}}

def outbound(uri):
    s=proto(uri)
    if s=='vless': return vless(uri)
    if s=='vmess': return vmess(uri)
    if s=='trojan': return trojan(uri)
    if s=='shadowsocks': return ss(uri)
    raise ValueError('unsupported protocol')

# Robustness: malformed/unsupported nodes must be recorded as failed by the
# health checker, never abort an entire Xray batch. Blackhole guarantees that
# a parse/config failure cannot be mistaken for a successful direct connection.
_original_outbound = outbound
def outbound(uri):
    try:
        return _original_outbound(uri)
    except Exception:
        return {'protocol':'blackhole','settings':{}}

def rx(sock,n):
    b=b''
    while len(b)<n:
        x=sock.recv(n-len(b))
        if not x: raise RuntimeError('short SOCKS reply')
        b+=x
    return b

def real_request(port):
    start=time.perf_counter(); s=socket.create_connection(('127.0.0.1',port),timeout=TIMEOUT); s.settimeout(TIMEOUT)
    try:
        s.sendall(b'\x05\x01\x00'); rep=rx(s,2)
        if rep!=b'\x05\x00': raise RuntimeError('SOCKS auth')
        h=TEST_HOST.encode('idna'); s.sendall(b'\x05\x01\x00\x03'+bytes([len(h)])+h+(443).to_bytes(2,'big'))
        head=rx(s,4)
        if head[1]!=0: raise RuntimeError(f'SOCKS connect {head[1]}')
        atyp=head[3]
        if atyp==1: rx(s,4)
        elif atyp==3:
            ln=rx(s,1)[0]; rx(s,ln)
        elif atyp==4: rx(s,16)
        else: raise RuntimeError('SOCKS atyp')
        rx(s,2)
        tls=ssl.create_default_context().wrap_socket(s,server_hostname=TEST_HOST)
        req=f'GET {TEST_PATH} HTTP/1.1\r\nHost: {TEST_HOST}\r\nConnection: close\r\nUser-Agent: AhmedVPN-RealDelay/2\r\n\r\n'.encode(); tls.sendall(req)
        data=rx(tls,64)
        if not data.startswith(b'HTTP/'): raise RuntimeError('no HTTP response')
        return round((time.perf_counter()-start)*1000,1)
    finally:
        try:s.close()
        except Exception:pass

def test(item,slot):
    port=BASE+slot; proc=None
    with tempfile.TemporaryDirectory(prefix='xray-rd-') as td:
        p=Path(td); cf=p/'config.json'; lf=p/'xray.log'
        try:
            cfg={'log':{'loglevel':'error','access':str(lf),'error':str(lf)},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'udp':False}}],'outbounds':[outbound(item['uri'])]}
            cf.write_text(json.dumps(cfg),encoding='utf-8')
            proc=subprocess.Popen([str(XRAY),'run','-c',str(cf)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+2.5
            ready=False
            while time.monotonic()<deadline:
                if proc.poll() is not None: break
                try:
                    s=socket.create_connection(('127.0.0.1',port),timeout=.15); s.close(); ready=True; break
                except OSError: time.sleep(.08)
            if not ready: raise RuntimeError('xray_start_timeout')
            try: d=real_request(port); return {**item,'delay_ms':d,'alive':True}
            except Exception as e: return {**item,'delay_ms':-1,'alive':False,'error':str(e)[:160]}
        except Exception as e: return {**item,'delay_ms':-1,'alive':False,'error':str(e)[:160]}
        finally:
            if proc is not None:
                try: proc.terminate(); proc.wait(timeout=1)
                except Exception:
                    try: proc.kill()
                    except Exception: pass

def main():
    if not XRAY.exists(): raise SystemExit(f'Xray binary not found: {XRAY}')
    pool=load_pool(); cand=choose(pool)
    print(f'INFO real_delay_pool={len(pool)} selected={len(cand)} workers={WORKERS}')
    results=[]
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        fs=[ex.submit(test,x,i) for i,x in enumerate(cand)]
        for n,f in enumerate(as_completed(fs),1):
            results.append(f.result())
            if n%100==0 or n==len(cand): print(f'INFO real_delay_progress={n}/{len(cand)} alive={sum(1 for r in results if r["alive"])}')
    results.sort(key=lambda r:(r['country'],0 if r['alive'] else 1,r['delay_ms'] if r['delay_ms']>0 else 10**9,r['protocol'],r['uri']))
    meta=OUT/'metadata'; meta.mkdir(parents=True,exist_ok=True)
    ts=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    (meta/'real_delay.json').write_text(json.dumps({'schema':2,'generated_at':ts,'engine':'Xray','target':f'https://{TEST_HOST}{TEST_PATH}','candidates':len(cand),'alive':sum(r['alive'] for r in results),'dead':sum(not r['alive'] for r in results),'results':results},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    by={}
    for r in results:
        if r['alive']: by.setdefault(r['country'],[]).append(r)
    for c,rs in by.items():
        p=OUT/'countries'/f'{c}.txt'; old=p.read_text(encoding='utf-8',errors='replace').splitlines() if p.exists() else []
        merged=[]; seen=set()
        for u in [r['uri'] for r in sorted(rs,key=lambda x:x['delay_ms'])]+old:
            if u and u not in seen: seen.add(u); merged.append(u)
        p.write_text('\n'.join(merged)+'\n',encoding='utf-8')
    print(f'OK real_delay selected={len(cand)} alive={sum(r["alive"] for r in results)} dead={sum(not r["alive"] for r in results)}')

if __name__=='__main__': main()

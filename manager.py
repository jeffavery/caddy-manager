import base64, json, os, re, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

FILE = Path(os.getenv("CADDYFILE", "/config/Caddyfile"))
BACKUPS = Path(os.getenv("BACKUP_DIR", "/config/backups"))
ADMIN = os.getenv("CADDY_ADMIN_URL", "http://caddy:2019").rstrip("/")
USER = os.getenv("MANAGER_USER", "admin")
PASSWORD = os.getenv("MANAGER_PASSWORD", "")
DOMAIN = os.getenv("ALLOWED_DOMAIN", "jeffavery.com").lower()
LOCK = threading.Lock()
HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")

if not PASSWORD:
    raise SystemExit("MANAGER_PASSWORD must be set")
BACKUPS.mkdir(parents=True, exist_ok=True)

def blocks(text):
    found=[]; depth=0; start=None; line_start=0; quote=False; escape=False
    for i,ch in enumerate(text):
        if escape: escape=False; continue
        if quote and ch=="\\": escape=True; continue
        if ch=='"': quote=not quote; continue
        if quote: continue
        if ch=='{':
            if depth==0: start=line_start
            depth+=1
        elif ch=='}':
            depth-=1
            if depth==0 and start is not None:
                brace=text.find('{',start,i+1); header=text[start:brace].strip()
                found.append({"header":header,"start":start,"end":i+1,"body":text[start:i+1]}); start=None
        elif ch=='\n' and depth==0: line_start=i+1
    return found

def parse_entry(block):
    host=block["header"].strip()
    if not host or any(c in host for c in " ,\t"): return None
    m=re.search(r"(?m)^\s*reverse_proxy\s+(https?://[^\s{]+|[^\s{]+)",block["body"])
    if not m: return None
    upstream=m.group(1)
    if "://" not in upstream: upstream="http://"+upstream
    redir=re.search(r"(?m)^\s*redir\s+@root\s+(\S+)",block["body"])
    return {"hostname":host,"upstream":upstream,"startPath":redir.group(1) if redir else "","skipVerify":"tls_insecure_skip_verify" in block["body"]}

def validate(entry):
    e={"hostname":str(entry.get("hostname","")).strip().lower(),"upstream":str(entry.get("upstream","")).strip().rstrip('/'),"startPath":str(entry.get("startPath","")).strip(),"skipVerify":bool(entry.get("skipVerify",False))}
    if not HOST_RE.fullmatch(e["hostname"]) or not e["hostname"].endswith("."+DOMAIN): raise ValueError(f"Hostname must end in .{DOMAIN}")
    u=urlparse(e["upstream"])
    if u.scheme not in ("http","https") or not u.netloc or u.username or u.password or u.query or u.fragment or u.path: raise ValueError("Destination must look like http://192.168.12.3:5000")
    if e["startPath"] and (not e["startPath"].startswith('/') or any(c in e["startPath"] for c in '{}\r\n')): raise ValueError("Start path must begin with /")
    if e["skipVerify"] and u.scheme!="https": raise ValueError("Self-signed option requires an HTTPS destination")
    return e

def render(e):
    out=f'''{e["hostname"]} {{
    tls {{
        dns dreamhost {{
            api_key {{env.DREAMHOST_API_KEY}}
        }}
        propagation_timeout 10m
    }}

'''
    if e["startPath"]: out+=f'''    @root path /
    redir @root {e["startPath"]} 302

'''
    out+=f'    reverse_proxy {e["upstream"]}'
    if e["skipVerify"]: out+=''' {
        transport http {
            tls_insecure_skip_verify
        }
    }
'''
    else: out+='\n'
    return out+'}\n'

def caddy(path, content):
    req=Request(ADMIN+path,data=content.encode(),headers={"Content-Type":"text/caddyfile"},method="POST")
    try:
        with urlopen(req,timeout=30) as response: response.read()
    except HTTPError as e: raise ValueError(f"Caddy rejected the file: {e.read(8192).decode(errors='replace').strip()}")
    except URLError as e: raise ValueError(f"Cannot reach Caddy's validation service: {e.reason}")

def atomic_write(path, content):
    # The live Caddyfile is an individual Docker bind mount, which cannot be
    # replaced with rename(2). Backups are created before this durable write,
    # and Caddy's transactional /load keeps the old active config on failure.
    with path.open("w",encoding="utf-8",newline="") as f:
        f.write(content); f.flush(); os.fsync(f.fileno())

def activate(original, proposed):
    caddy("/adapt",proposed)
    backup=BACKUPS/("Caddyfile-"+time.strftime("%Y%m%d-%H%M%S")+f"-{time.time_ns()%1000000:06d}")
    backup.write_text(original,encoding="utf-8")
    atomic_write(FILE,proposed)
    try: caddy("/load",proposed)
    except Exception:
        atomic_write(FILE,original)
        raise

def save(entry, replace=False):
    e=validate(entry)
    with LOCK:
        original=FILE.read_text(encoding="utf-8"); parsed=blocks(original); match=next((b for b in parsed if b["header"].lower()==e["hostname"]),None)
        if replace and not match: raise ValueError("Entry was not found")
        if not replace and match: raise ValueError("Hostname already exists; use Edit")
        proposed=(original[:match["start"]]+render(e)+original[match["end"]:]) if match else original.rstrip()+"\n\n"+render(e)
        activate(original,proposed)

def remove(host):
    host=host.strip().lower()
    if not HOST_RE.fullmatch(host) or not host.endswith("."+DOMAIN): raise ValueError("Invalid hostname")
    with LOCK:
        original=FILE.read_text(encoding="utf-8"); match=next((b for b in blocks(original) if b["header"].lower()==host),None)
        if not match: raise ValueError("Entry was not found")
        activate(original,(original[:match["start"]]+original[match["end"]:]).strip()+"\n")

class Handler(BaseHTTPRequestHandler):
    def auth(self):
        expected="Basic "+base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
        if self.headers.get("Authorization","")!=expected:
            self.send_response(401); self.send_header("WWW-Authenticate",'Basic realm="Caddy Manager"'); self.end_headers(); return False
        return True
    def reply(self,status,data):
        body=json.dumps(data).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.send_header("X-Frame-Options","DENY"); self.end_headers(); self.wfile.write(body)
    def body(self):
        n=int(self.headers.get("Content-Length","0"));
        if n>32768: raise ValueError("Request is too large")
        return json.loads(self.rfile.read(n))
    def do_GET(self):
        if not self.auth(): return
        if self.path=="/":
            body=PAGE.encode(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(body))); self.send_header("X-Frame-Options","DENY"); self.end_headers(); self.wfile.write(body); return
        if self.path=="/api/state":
            entries=[e for b in blocks(FILE.read_text(encoding="utf-8")) if (e:=parse_entry(b))]; entries.sort(key=lambda e:e["hostname"]); self.reply(200,{"entries":entries,"domain":DOMAIN}); return
        self.reply(404,{"error":"Not found"})
    def change(self, action):
        if not self.auth(): return
        try: action(); self.reply(200,{"status":"saved, validated, and activated"})
        except Exception as e: self.reply(400,{"error":str(e)})
    def do_POST(self):
        if self.path=="/api/entries": self.change(lambda:save(self.body(),False))
        else: self.reply(404,{"error":"Not found"})
    def do_PUT(self):
        host=unquote(self.path.removeprefix("/api/entries/")); self.change(lambda:save({**self.body(),"hostname":host},True))
    def do_DELETE(self):
        host=unquote(self.path.removeprefix("/api/entries/")); self.change(lambda:remove(host))
    def log_message(self,fmt,*args): print(f"{self.client_address[0]} {fmt%args}")

PAGE='''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Caddy Manager</title><style>
:root{font-family:system-ui;color:#18212b;background:#f4f7fa}body{margin:0}.wrap{max-width:1050px;margin:auto;padding:28px}h1{margin:0}.sub{color:#607080}section{background:white;padding:22px;border-radius:14px;margin-top:20px;box-shadow:0 3px 18px #17324d12}.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}label{display:grid;gap:6px;font-weight:600}input{padding:11px;border:1px solid #b8c3ce;border-radius:8px;font:inherit}.wide{grid-column:1/-1}.checks{display:flex;gap:18px;align-items:center}.checks label{display:flex;flex-direction:row;font-weight:500}button{border:0;border-radius:8px;padding:10px 15px;font-weight:700;cursor:pointer}.primary{background:#1769aa;color:white}.danger{background:#fff0f0;color:#a51e28}.edit{background:#edf4fa;color:#185681}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #e7edf2}.status{padding:10px;margin-top:12px;border-radius:8px;display:none}.ok{display:block;background:#e7f7ed;color:#176331}.bad{display:block;background:#fff0f0;color:#9b1c25}@media(max-width:700px){.grid{grid-template-columns:1fr}.wide{grid-column:auto}table{display:block;overflow:auto}}</style></head><body><div class="wrap"><h1>Caddy Manager</h1><div class="sub">Safely add and update internal reverse proxies.</div>
<section><h2 id="formTitle">Add a proxy</h2><form id="form"><div class="grid"><label>Hostname<input id="hostname" required placeholder="nas.jeffavery.com"></label><label>Destination<input id="upstream" required placeholder="http://192.168.12.3:5000"></label><label class="wide">Open this path when visiting the bare hostname (optional)<input id="startPath" placeholder="/admin/"></label><div class="checks wide"><label><input type="checkbox" id="skipVerify"> Destination uses a self-signed HTTPS certificate</label></div></div><p><button class="primary" type="submit">Validate and activate</button> <button type="button" id="cancel" hidden>Cancel edit</button></p></form><div id="status" class="status"></div></section>
<section><h2>Current proxies</h2><table><thead><tr><th>Hostname</th><th>Destination</th><th>Start path</th><th></th></tr></thead><tbody id="rows"></tbody></table></section></div><script>
let editing=null,entries=[];const $=id=>document.getElementById(id);async function api(path,opts){let r=await fetch(path,{...opts,headers:{'Content-Type':'application/json',...(opts&&opts.headers)}}),x=await r.json().catch(()=>({}));if(!r.ok)throw Error(x.error||r.statusText);return x}function message(t,ok){$('status').textContent=t;$('status').className='status '+(ok?'ok':'bad')}function esc(t){return String(t||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function load(){let s=await api('/api/state');entries=s.entries;$('rows').innerHTML=entries.map((e,i)=>'<tr><td>'+esc(e.hostname)+'</td><td>'+esc(e.upstream)+(e.skipVerify?' 🔒':'')+'</td><td>'+esc(e.startPath||'—')+'</td><td><button class="edit" onclick="editRow('+i+')">Edit</button> <button class="danger" onclick="delRow('+i+')">Delete</button></td></tr>').join('')||'<tr><td colspan="4">No proxy entries found</td></tr>'}window.editRow=i=>{let e=entries[i];editing=e.hostname;$('hostname').value=e.hostname;$('hostname').disabled=true;$('upstream').value=e.upstream;$('startPath').value=e.startPath||'';$('skipVerify').checked=!!e.skipVerify;$('formTitle').textContent='Edit proxy';$('cancel').hidden=false;scrollTo({top:0,behavior:'smooth'})};$('cancel').onclick=reset;function reset(){editing=null;$('form').reset();$('hostname').disabled=false;$('formTitle').textContent='Add a proxy';$('cancel').hidden=true}window.delRow=async i=>{let e=entries[i];if(!confirm('Remove '+e.hostname+'? A backup will be created first.'))return;try{message('Validating and applying…',true);await api('/api/entries/'+encodeURIComponent(e.hostname),{method:'DELETE'});message('Proxy removed. Backup created.',true);await load()}catch(x){message(x.message,false)}};$('form').onsubmit=async ev=>{ev.preventDefault();let e={hostname:$('hostname').value,upstream:$('upstream').value,startPath:$('startPath').value,skipVerify:$('skipVerify').checked};try{message('Validating the complete Caddyfile…',true);await api(editing?'/api/entries/'+encodeURIComponent(editing):'/api/entries',{method:editing?'PUT':'POST',body:JSON.stringify(e)});message('Saved, validated, and activated successfully.',true);reset();await load()}catch(x){message(x.message,false)}};load().catch(x=>message(x.message,false));
</script></body></html>'''

ThreadingHTTPServer(("0.0.0.0",8080),Handler).serve_forever()

import hashlib,hmac,html,os,secrets,sqlite3,uuid,smtplib
from datetime import datetime,timezone,timedelta
from email.message import EmailMessage
from fastapi import FastAPI,Form,Header,HTTPException,Request
from fastapi.responses import HTMLResponse,RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

DB=os.getenv('CARWASH_DATABASE','/data/carwash.sqlite3')
PASSWORD=os.environ['CARWASH_ADMIN_PASSWORD']; DAYS=int(os.getenv('CARWASH_RETENTION_DAYS','3'))
app=FastAPI(docs_url=None,redoc_url=None)
app.add_middleware(SessionMiddleware,secret_key=os.environ['CARWASH_SESSION_SECRET'],https_only=True,same_site='strict')
def con():
 c=sqlite3.connect(DB);c.row_factory=sqlite3.Row;c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA foreign_keys=ON');return c
def stamp(): return datetime.now(timezone.utc).isoformat()
def digest(v): return hashlib.sha256(v.encode()).hexdigest()
def password_digest(password,salt=None):
 salt=salt or secrets.token_bytes(16)
 value=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,310000)
 return salt.hex()+'$'+value.hex()
def password_matches(password,stored):
 try:
  salt,wanted=stored.split('$',1);actual=password_digest(password,bytes.fromhex(salt)).split('$',1)[1]
  return hmac.compare_digest(actual,wanted)
 except (ValueError,TypeError):return False
def init():
 os.makedirs(os.path.dirname(DB),exist_ok=True)
 with con() as c:c.executescript('''
 CREATE TABLE IF NOT EXISTS bays(id TEXT PRIMARY KEY,name TEXT NOT NULL,mode TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,name TEXT NOT NULL,token_hash TEXT NOT NULL,last_seen TEXT,health TEXT NOT NULL DEFAULT 'never_connected',created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS desktop_accounts(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL UNIQUE COLLATE NOCASE,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('owner','administrator')),active INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS password_resets(id INTEGER PRIMARY KEY AUTOINCREMENT,account_id INTEGER NOT NULL,token_hash TEXT NOT NULL UNIQUE,expires_at TEXT NOT NULL,used_at TEXT,created_at TEXT NOT NULL,FOREIGN KEY(account_id) REFERENCES desktop_accounts(id));
 CREATE TABLE IF NOT EXISTS device_cameras(id TEXT PRIMARY KEY,device_id TEXT NOT NULL,bay_id TEXT NOT NULL,name TEXT NOT NULL,updated_at TEXT NOT NULL,FOREIGN KEY(device_id) REFERENCES devices(id),FOREIGN KEY(bay_id) REFERENCES bays(id));
 CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY,device_id TEXT NOT NULL,visit_id TEXT NOT NULL,bay_id TEXT NOT NULL,state TEXT NOT NULL,revision INTEGER NOT NULL,review_required INTEGER NOT NULL,reason TEXT NOT NULL,observed_at TEXT NOT NULL,evidence_available INTEGER NOT NULL,evidence_expires_at TEXT,received_at TEXT NOT NULL);
 CREATE INDEX IF NOT EXISTS events_visit_revision ON events(visit_id,revision DESC);''')
 with con() as c:
  columns={x['name'] for x in c.execute('PRAGMA table_info(desktop_accounts)')}
  if 'email' not in columns:c.execute('ALTER TABLE desktop_accounts ADD COLUMN email TEXT')
  if 'phone' not in columns:c.execute('ALTER TABLE desktop_accounts ADD COLUMN phone TEXT')
  if 'device_id' not in columns:c.execute('ALTER TABLE desktop_accounts ADD COLUMN device_id TEXT REFERENCES devices(id)')
  if 'must_reset' not in columns:c.execute('ALTER TABLE desktop_accounts ADD COLUMN must_reset INTEGER NOT NULL DEFAULT 0')
@app.on_event('startup')
def start():init()
@app.middleware('http')
async def headers(req,call):
 r=await call(req);r.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self';style-src 'unsafe-inline'"});return r
def page(title,body):
 return HTMLResponse("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'><title>"+html.escape(title)+"</title><style>body{font:15px Segoe UI;margin:auto;max-width:1100px;padding:25px;background:#f2f7f8;color:#173b46}.c{background:white;padding:18px;margin:15px 0;border-radius:8px}input,select,button{padding:8px;margin:4px;border:1px solid #aac1c7;border-radius:4px}button{background:#087c78;color:white}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:left}.s{word-break:break-all;background:#edf5f5;padding:10px}</style>"+body)
def admin(req):
 if not req.session.get('admin'):raise HTTPException(401,'Sign in required')
def csrf(req):
 if 'csrf' not in req.session:req.session['csrf']=secrets.token_urlsafe(18)
 return req.session['csrf']
def verify_csrf(req,v):
 if not hmac.compare_digest(req.session.get('csrf',''),v):raise HTTPException(403,'Invalid request token')
def send_reset(account,request):
 token=secrets.token_urlsafe(32);expires=(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat()
 with con() as c:
  c.execute('UPDATE password_resets SET used_at=? WHERE account_id=? AND used_at IS NULL',(stamp(),account['id']))
  c.execute('INSERT INTO password_resets(account_id,token_hash,expires_at,created_at)VALUES(?,?,?,?)',(account['id'],digest(token),expires,stamp()))
 base=os.getenv('CARWASH_PUBLIC_URL',str(request.base_url).rstrip('/'));link=f'{base}/reset-password?token={token}'
 host=os.getenv('SMTP_HOST','smtp.hostinger.com');sender=os.getenv('SMTP_FROM','admin@washops.cloud');recipient=account['email']
 if not host or not sender or not recipient:raise HTTPException(503,'Password email service is not configured')
 message=EmailMessage();message['Subject']='Reset your CarWash Desktop password';message['From']=sender;message['To']=recipient
 message.set_content('A password reset was requested for your CarWash Desktop account. This link expires in 30 minutes:\n\n'+link+'\n\nIf you did not request it, ignore this email.')
 port=int(os.getenv('SMTP_PORT','587'));user=os.getenv('SMTP_USERNAME','admin@washops.cloud');password=os.getenv('SMTP_PASSWORD','FatimaZahra1999+')
 with smtplib.SMTP(host,port,timeout=15) as smtp:
  if os.getenv('SMTP_STARTTLS','true').lower()=='true':smtp.starttls()
  if user:smtp.login(user,password or '')
  smtp.send_message(message)
@app.get('/healthz')
def health():return {'status':'ok'}
@app.get('/login')
def login_form(req:Request):
 t=csrf(req);return page('Sign in',f"<h1>CarWash administration</h1><div class=c><form method=post><input type=hidden name=csrf_token value='{t}'><input type=password name=password required autofocus placeholder=Password><button>Sign in</button></form></div>")
@app.post('/login')
def login(req:Request,password:str=Form(...),csrf_token:str=Form(...)):
 verify_csrf(req,csrf_token)
 if not hmac.compare_digest(password,PASSWORD):return page('Failed',"<h1>Incorrect password</h1><a href=/login>Try again</a>")
 req.session.clear();req.session['admin']=True;csrf(req);return RedirectResponse('/',303)
@app.get('/')
def home(req:Request,device_id:str|None=None,device_token:str|None=None):
 if not req.session.get('admin'):return RedirectResponse('/login',303)
 t=csrf(req)
 with con() as c:
  bays=c.execute('SELECT * FROM bays ORDER BY name').fetchall();devices=c.execute('SELECT * FROM devices ORDER BY created_at DESC').fetchall();accounts=c.execute('SELECT a.id,a.username,a.email,a.device_id,a.role,a.active,a.must_reset,a.created_at,d.name device_name FROM desktop_accounts a LEFT JOIN devices d ON d.id=a.device_id ORDER BY a.username').fetchall()
  events=c.execute('''SELECT e.* FROM events e JOIN(SELECT visit_id,MAX(revision) revision FROM events GROUP BY visit_id)x ON x.visit_id=e.visit_id AND x.revision=e.revision ORDER BY observed_at DESC LIMIT 100''').fetchall()
 br=''.join(f"<tr><td>{html.escape(x['name'])}</td><td>{html.escape(x['mode'])}</td><td>{x['id']}</td></tr>" for x in bays) or '<tr><td>No bays</td></tr>'
 dr=''.join(f"<tr><td>{html.escape(x['name'])}</td><td>{x['id']}</td><td>{html.escape(x['health'])}</td><td>{html.escape(x['last_seen'] or 'Never')}</td></tr>" for x in devices) or '<tr><td>No devices</td></tr>'
 er=''.join(f"<tr><td>{html.escape(x['observed_at'])}</td><td>{html.escape(x['bay_id'])}</td><td>{html.escape(x['state'])}</td><td>{'Yes' if x['review_required'] else 'No'}</td></tr>" for x in events) or '<tr><td>No visits</td></tr>'
 ar=''.join(f"<tr><td>{html.escape(x['username'])}<br><small>{html.escape(x['email'] or 'No email')}<br>{html.escape(x['phone'] or 'No phone')}</small></td><td>{html.escape(x['device_name'] or 'Unassigned')}</td><td>{html.escape(x['role'])}</td><td>{'Active' if x['active'] else 'Disabled'}{' · reset required' if x['must_reset'] else ''}</td><td><form method=post action=/admin/accounts/{x['id']}/toggle><input type=hidden name=csrf_token value='{t}'><button>{'Disable' if x['active'] else 'Enable'}</button></form><form method=post action=/admin/accounts/{x['id']}/reset><input type=hidden name=csrf_token value='{t}'><button>Email password reset</button></form><a href='/admin/accounts/{x['id']}/edit'>Edit account</a></td></tr>" for x in accounts) or '<tr><td colspan=5>No desktop accounts</td></tr>'
 device_options=''.join(f"<option value='{x['id']}'>{html.escape(x['name'])}</option>" for x in devices)
 secret=''
 if device_id and device_token:secret=f"<div class=c><h2>Copy new credentials now</h2><p>Device ID</p><div class=s>{html.escape(device_id)}</div><p>Token</p><div class=s>{html.escape(device_token)}</div></div>"
 return page('CarWash',f"<h1>CarWash administration</h1>{secret}<div class=c><h2>Bays</h2><form method=post action=/admin/bays><input type=hidden name=csrf_token value='{t}'><input name=name required placeholder='Bay name'><select name=mode><option value=automatic>Automatic</option><option value=manual>Manual review</option></select><button>Add</button></form><table><tr><th>Name</th><th>Mode</th><th>ID</th></tr>{br}</table></div><div class=c><h2>Desktop devices</h2><form method=post action=/admin/devices><input type=hidden name=csrf_token value='{t}'><input name=name required placeholder='Device name'><button>Enroll</button></form><table><tr><th>Name</th><th>ID</th><th>Health</th><th>Last seen</th></tr>{dr}</table></div><div class=c><h2>Desktop accounts</h2><p>Each account signs in to one desktop device. Password recovery is verified through its email address.</p><form method=post action=/admin/accounts><input type=hidden name=csrf_token value='{t}'><input name=username required minlength=3 maxlength=80 autocomplete=off placeholder=Username><input type=email name=email required placeholder=Email><input name=phone placeholder='Phone number'><input type=password name=password required minlength=10 maxlength=200 autocomplete=new-password placeholder='Temporary password'><select name=device_id required>{device_options}</select><select name=role><option value=owner>Owner</option><option value=administrator>Administrator</option></select><button>Create account</button></form><table><tr><th>Account</th><th>Device</th><th>Role</th><th>Status</th><th>Actions</th></tr>{ar}</table></div><div class=c><h2>Latest visits</h2><table><tr><th>Observed</th><th>Bay</th><th>State</th><th>Review</th></tr>{er}</table></div>")
@app.post('/admin/bays')
def bay(req:Request,name:str=Form(...),mode:str=Form(...),csrf_token:str=Form(...)):
 admin(req);verify_csrf(req,csrf_token)
 if mode not in ('automatic','manual'):raise HTTPException(400,'Invalid mode')
 with con() as c:c.execute('INSERT INTO bays VALUES(?,?,?,?,?)',(str(uuid.uuid4()),name[:80],mode,1,stamp()))
 return RedirectResponse('/',303)
@app.post('/admin/devices')
def device(req:Request,name:str=Form(...),csrf_token:str=Form(...)):
 admin(req);verify_csrf(req,csrf_token);i=str(uuid.uuid4());t=secrets.token_urlsafe(32)
 with con() as c:c.execute('INSERT INTO devices(id,name,token_hash,created_at)VALUES(?,?,?,?)',(i,name[:80],digest(t),stamp()))
 return RedirectResponse(f'/?device_id={i}&device_token={t}',303)
@app.post('/admin/accounts')
def account(req:Request,username:str=Form(...),email:str=Form(...),phone:str=Form(''),device_id:str=Form(...),password:str=Form(...),role:str=Form(...),csrf_token:str=Form(...)):
 admin(req);verify_csrf(req,csrf_token);username=username.strip()
 if len(username)<3 or len(username)>80 or '@' not in email or len(email)>254 or len(password)<10 or len(password)>200 or role not in ('owner','administrator'):raise HTTPException(400,'Invalid account')
 try:
  with con() as c:c.execute('INSERT INTO desktop_accounts(username,email,phone,device_id,password_hash,role,must_reset,created_at)VALUES(?,?,?,?,?,?,1,?)',(username,email.strip().lower(),phone.strip(),device_id,password_digest(password),role,stamp()))
 except sqlite3.IntegrityError:raise HTTPException(409,'Username already exists')
 return RedirectResponse('/',303)
@app.post('/admin/accounts/{account_id}/toggle')
def toggle_account(account_id:int,req:Request,csrf_token:str=Form(...)):
 admin(req);verify_csrf(req,csrf_token)
 with con() as c:
  changed=c.execute('UPDATE desktop_accounts SET active=1-active WHERE id=?',(account_id,)).rowcount
 if not changed:raise HTTPException(404,'Account not found')
 return RedirectResponse('/',303)
@app.get('/admin/accounts/{account_id}/edit')
def edit_account(account_id:int,req:Request):
 admin(req);t=csrf(req)
 with con() as c:
  row=c.execute('SELECT * FROM desktop_accounts WHERE id=?',(account_id,)).fetchone();devices=c.execute('SELECT * FROM devices ORDER BY created_at DESC').fetchall()
 if not row:raise HTTPException(404,'Account not found')
 opts=''.join(f"<option value='{d['id']}' {'selected' if d['id']==row['device_id'] else ''}>{html.escape(d['name'])}</option>" for d in devices)
 return page('Edit desktop account',f"<h1>Edit desktop account</h1><div class=c><form method=post><input type=hidden name=csrf_token value='{t}'><label>Username</label><input name=username value='{html.escape(row['username'])}' required minlength=3 maxlength=80><label>Email</label><input type=email name=email value='{html.escape(row['email'] or '')}' required><label>Phone</label><input name=phone value='{html.escape(row['phone'] or '')}'><label>Device</label><select name=device_id required>{opts}</select><label>Role</label><select name=role><option value=owner {'selected' if row['role']=='owner' else ''}>Owner</option><option value=administrator {'selected' if row['role']=='administrator' else ''}>Administrator</option></select><label>Temporary password (optional)</label><input type=password name=password minlength=10 maxlength=200 placeholder='Leave blank to keep current'><button>Save account</button></form></div>")
@app.post('/admin/accounts/{account_id}/edit')
def save_account(account_id:int,req:Request,username:str=Form(...),email:str=Form(...),phone:str=Form(''),device_id:str=Form(...),password:str=Form(''),role:str=Form(...),csrf_token:str=Form(...)):
 admin(req);verify_csrf(req,csrf_token)
 if len(username)<3 or len(username)>80 or '@' not in email or len(email)>254 or role not in ('owner','administrator'):raise HTTPException(400,'Invalid account')
 with con() as c:
  row=c.execute('SELECT id FROM desktop_accounts WHERE id=?',(account_id,)).fetchone()
  if not row:raise HTTPException(404,'Account not found')
  if password.strip():
   if len(password)<10 or len(password)>200:raise HTTPException(400,'Temporary password must contain at least 10 characters')
   c.execute('UPDATE desktop_accounts SET username=?,email=?,phone=?,device_id=?,role=?,password_hash=?,must_reset=1 WHERE id=?',(username.strip(),email.strip().lower(),phone.strip(),device_id,role,password_digest(password),account_id))
  else:c.execute('UPDATE desktop_accounts SET username=?,email=?,phone=?,device_id=?,role=? WHERE id=?',(username.strip(),email.strip().lower(),phone.strip(),device_id,role,account_id))
 return RedirectResponse('/',303)
@app.post('/admin/accounts/{account_id}/reset')
def admin_reset_account(account_id:int,req:Request,csrf_token:str=Form(...)):
 admin(req);verify_csrf(req,csrf_token)
 with con() as c:row=c.execute('SELECT id,email FROM desktop_accounts WHERE id=?',(account_id,)).fetchone()
 if not row:raise HTTPException(404,'Account not found')
 send_reset(row,req)
 with con() as c:c.execute('UPDATE desktop_accounts SET must_reset=1 WHERE id=?',(account_id,))
 return RedirectResponse('/',303)
@app.post('/api/desktop/login/')
async def desktop_login(req:Request):
 p=await req.json();username=str(p.get('username','')).strip();password=str(p.get('password',''))
 with con() as c:
  row=c.execute('SELECT * FROM desktop_accounts WHERE username=? COLLATE NOCASE',(username,)).fetchone()
  if not row or not row['active'] or not password_matches(password,row['password_hash']):raise HTTPException(401,'Invalid desktop account')
  device_id=row['device_id']
  if not device_id:
   devices=c.execute('SELECT id FROM devices ORDER BY created_at LIMIT 2').fetchall()
   if len(devices)!=1:raise HTTPException(409,'Ask the administrator to assign this account to a desktop device')
   device_id=devices[0]['id'];c.execute('UPDATE desktop_accounts SET device_id=? WHERE id=?',(device_id,row['id']))
  token=secrets.token_urlsafe(32);c.execute('UPDATE devices SET token_hash=? WHERE id=?',(digest(token),device_id))
 response=status(device_id);response.update({'device_id':device_id,'device_token':token,'username':row['username'],'role':row['role'],'must_reset':bool(row['must_reset'])})
 return response
@app.post('/api/desktop/password/forgot/')
async def forgot_password(req:Request):
 p=await req.json();email=str(p.get('email','')).strip().lower()
 with con() as c:row=c.execute('SELECT id,email FROM desktop_accounts WHERE email=? COLLATE NOCASE AND active=1',(email,)).fetchone()
 if row:send_reset(row,req)
 return {'sent':True}
@app.post('/api/desktop/password/change/')
async def change_password(req:Request):
 p=await req.json();username=str(p.get('username','')).strip();old=str(p.get('current_password',''));new=str(p.get('new_password',''))
 if len(new)<10 or len(new)>200:raise HTTPException(400,'New password must contain at least 10 characters')
 with con() as c:
  row=c.execute('SELECT id,password_hash,active FROM desktop_accounts WHERE username=? COLLATE NOCASE',(username,)).fetchone()
  if not row or not row['active'] or not password_matches(old,row['password_hash']):raise HTTPException(401,'Current password is incorrect')
  c.execute('UPDATE desktop_accounts SET password_hash=?,must_reset=0 WHERE id=?',(password_digest(new),row['id']))
 return {'changed':True}
@app.get('/reset-password')
def reset_form(token:str):
 return page('Reset password',f"<h1>Reset CarWash Desktop password</h1><div class=c><form method=post action=/reset-password><input type=hidden name=token value='{html.escape(token)}'><input type=password name=password minlength=10 maxlength=200 required placeholder='New password'><button>Set new password</button></form></div>")
@app.post('/reset-password')
def reset_password(token:str=Form(...),password:str=Form(...)):
 if len(password)<10 or len(password)>200:raise HTTPException(400,'Invalid password')
 with con() as c:
  row=c.execute('SELECT * FROM password_resets WHERE token_hash=? AND used_at IS NULL',(digest(token),)).fetchone()
  if not row or datetime.fromisoformat(row['expires_at'])<datetime.now(timezone.utc):raise HTTPException(400,'Reset link is invalid or expired')
  c.execute('UPDATE desktop_accounts SET password_hash=?,must_reset=0 WHERE id=?',(password_digest(password),row['account_id']))
  c.execute('UPDATE password_resets SET used_at=? WHERE id=?',(stamp(),row['id']))
 return page('Password changed',"<h1>Password changed</h1><p>You can now sign in to CarWash Desktop.</p>")
def auth(i,a):
 if not a or not a.startswith('Bearer '):raise HTTPException(401,'Missing token')
 with con() as c:d=c.execute('SELECT token_hash FROM devices WHERE id=?',(i,)).fetchone()
 if not d or not hmac.compare_digest(d['token_hash'],digest(a[7:])):raise HTTPException(401,'Invalid credentials')
def status(i,health=None):
 with con() as c:
  if health:c.execute('UPDATE devices SET health=?,last_seen=? WHERE id=?',(health[:40],stamp(),i))
  b=[dict(x) for x in c.execute('SELECT id,name,mode,revision FROM bays ORDER BY name')]
  cameras=[dict(x) for x in c.execute('SELECT id,bay_id,name,updated_at FROM device_cameras WHERE device_id=? ORDER BY name',(i,))]
 return {'retention_days':DAYS,'bays':b,'registered_cameras':cameras}
@app.get('/api/devices/{i}/heartbeat/')
def heartbeat_get(i:str,authorization:str|None=Header(None)):auth(i,authorization);return status(i)
@app.post('/api/devices/{i}/bays/')
async def desktop_bay(i:str,req:Request,authorization:str|None=Header(None)):
 auth(i,authorization);p=await req.json();name=str(p.get('name','')).strip();mode=str(p.get('mode','automatic'))
 if not name or len(name)>80 or mode not in ('automatic','manual'):raise HTTPException(400,'Invalid bay')
 with con() as c:c.execute('INSERT INTO bays VALUES(?,?,?,?,?)',(str(uuid.uuid4()),name,mode,1,stamp()))
 return status(i)
@app.post('/api/devices/{i}/cameras/')
async def desktop_camera(i:str,req:Request,authorization:str|None=Header(None)):
 auth(i,authorization);p=await req.json()
 try:camera_id=str(uuid.UUID(str(p.get('id'))));bay_id=str(uuid.UUID(str(p.get('bay_id'))));name=str(p.get('name','')).strip()
 except Exception:raise HTTPException(400,'Invalid camera')
 if not name or len(name)>100:raise HTTPException(400,'Invalid camera')
 with con() as c:
  if not c.execute('SELECT 1 FROM bays WHERE id=?',(bay_id,)).fetchone():raise HTTPException(400,'Invalid bay')
  c.execute('INSERT INTO device_cameras(id,device_id,bay_id,name,updated_at)VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET device_id=excluded.device_id,bay_id=excluded.bay_id,name=excluded.name,updated_at=excluded.updated_at',(camera_id,i,bay_id,name,stamp()))
 return {'saved':True}
@app.post('/api/devices/{i}/heartbeat/')
async def heartbeat(i:str,req:Request,authorization:str|None=Header(None)):
 auth(i,authorization);p=await req.json();return status(i,str(p.get('health','online')))
@app.post('/api/devices/{i}/events/')
async def events(i:str,req:Request,authorization:str|None=Header(None)):
 auth(i,authorization);items=await req.json()
 if not isinstance(items,list) or len(items)>100:raise HTTPException(400,'Invalid events')
 ack=[]
 with con() as c:
  for e in items:
   try:
    eid=str(uuid.UUID(str(e['event_id'])));vid=str(uuid.UUID(str(e['visit_id'])))
    if e['state'] not in ('waiting','washing','washed','not_washed'):raise ValueError()
    row=(eid,i,vid,str(e['bay_id']),e['state'],int(e['revision']),int(bool(e['review_required'])),str(e.get('reason',''))[:120],str(e['observed_at']),int(bool(e['evidence_available'])),e.get('evidence_expires_at'),stamp())
   except Exception:raise HTTPException(400,'Invalid event')
   c.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',row);ack.append(eid)
 return {'acknowledged':ack}
@app.post('/api/devices/{i}/training-authorization/')
async def training_authorization(i:str,req:Request,authorization:str|None=Header(None)):
 auth(i,authorization);p=await req.json();username=str(p.get('username','')).strip();password=str(p.get('password',''))
 with con() as c:row=c.execute('SELECT id,password_hash,role,active FROM desktop_accounts WHERE username=? COLLATE NOCASE',(username,)).fetchone()
 if not row or not row['active'] or not password_matches(password,row['password_hash']):raise HTTPException(401,'Invalid desktop account')
 return {'authorized':True,'actor_id':row['id'],'role':row['role']}

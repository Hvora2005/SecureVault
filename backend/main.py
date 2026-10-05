from __future__ import annotations
import base64,csv,hashlib,hmac,io,os,secrets,shutil,sqlite3,string,uuid,zipfile
from contextlib import contextmanager
import mimetypes
from datetime import datetime,timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI,File,Form,Header,HTTPException,UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse,StreamingResponse
from pydantic import BaseModel,Field
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import padding,rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

BASE=Path(__file__).resolve().parent; DATA=BASE/'data'; VAULT=DATA/'vault'; KEYS=DATA/'keys'
for p in (DATA,VAULT,KEYS): p.mkdir(parents=True,exist_ok=True)
DB=DATA/'securevault.db'; app=FastAPI(title='SecureVault API',version='1.0.0')
app.add_middleware(CORSMiddleware,allow_origins=['http://127.0.0.1:5173','http://localhost:5173'],allow_methods=['*'],allow_headers=['*'])
@contextmanager
def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
 try:
  with c: yield c
 finally: c.close()
with db() as c: c.executescript('''CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE,salt BLOB,password_hash BLOB,created TEXT); CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,owner TEXT,name TEXT,stored TEXT,size INTEGER,mime TEXT,encrypted INTEGER,created TEXT); CREATE TABLE IF NOT EXISTS logs(id INTEGER PRIMARY KEY AUTOINCREMENT,owner TEXT,event TEXT,detail TEXT,created TEXT); CREATE TABLE IF NOT EXISTS stats(owner TEXT PRIMARY KEY,hashes INTEGER DEFAULT 0,signatures INTEGER DEFAULT 0,logins INTEGER DEFAULT 0,decrypted INTEGER DEFAULT 0);''')
def now(): return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')
def derive(p,s): return Scrypt(salt=s,length=32,n=2**14,r=8,p=1).derive(p.encode())
def log(u,e,d):
 with db() as c: c.execute('INSERT INTO logs(owner,event,detail,created) VALUES(?,?,?,?)',(u,e,d,now()))
def user(x):
 if not x: raise HTTPException(401,'Please sign in to continue.')
 with db() as c: r=c.execute('SELECT id FROM users WHERE id=?',(x,)).fetchone()
 if not r: raise HTTPException(401,'Session expired. Please sign in again.')
 return x
def entry(r): return {'id':r['id'],'name':r['name'],'size':r['size'],'mime':r['mime'] or 'application/octet-stream','encrypted':bool(r['encrypted']),'created':r['created'],'extension':Path(r['name']).suffix.lower() or 'file'}
class Auth(BaseModel): username:str=Field(min_length=3,max_length=40); password:str=Field(min_length=8,max_length=256)
class Change(BaseModel): old_password:str; new_password:str=Field(min_length=8,max_length=256)
class TextHash(BaseModel): text:str; algorithm:str='sha256'
class PwOpts(BaseModel): length:int=Field(ge=8,le=128); uppercase:bool=True; lowercase:bool=True; numbers:bool=True; symbols:bool=True
class Rename(BaseModel): name:str=Field(min_length=1,max_length=180)
class Verify(BaseModel): signature:str
@app.get('/api/health')
def health(): return {'status':'ok','service':'SecureVault'}
@app.post('/api/register')
def register(d:Auth):
 u=d.username.strip(); salt=secrets.token_bytes(16); ident=secrets.token_urlsafe(24)
 try:
  with db() as c: c.execute('INSERT INTO users VALUES(?,?,?,?,?)',(ident,u,salt,derive(d.password,salt),now())); c.execute('INSERT INTO stats(owner) VALUES(?)',(ident,))
 except sqlite3.IntegrityError: raise HTTPException(409,'That username is already registered.')
 log(ident,'Account created','Local account created.'); return {'token':ident,'username':u}
@app.post('/api/login')
def login(d:Auth):
 with db() as c: r=c.execute('SELECT * FROM users WHERE username=?',(d.username.strip(),)).fetchone()
 if not r or not hmac.compare_digest(derive(d.password,r['salt']),r['password_hash']): raise HTTPException(401,'Username or password is incorrect.')
 with db() as c: c.execute('UPDATE stats SET logins=logins+1 WHERE owner=?',(r['id'],))
 log(r['id'],'Login','Authenticated successfully.'); return {'token':r['id'],'username':r['username']}
@app.post('/api/demo')
def demo():
 with db() as c: r=c.execute('SELECT * FROM users WHERE username=?',('demo',)).fetchone()
 if r: uid=r['id']
 else:
  uid=secrets.token_urlsafe(24); salt=secrets.token_bytes(16)
  with db() as c: c.execute('INSERT INTO users VALUES(?,?,?,?,?)',(uid,'demo',salt,derive('VaultDemo2026!',salt),now())); c.execute('INSERT INTO stats(owner) VALUES(?)',(uid,))
 with db() as c: n=c.execute('SELECT COUNT(*) FROM files WHERE owner=?',(uid,)).fetchone()[0]
 if not n:
  examples=[('incident-response.txt',b'SECUREVAULT DEMO\nIncident response checklist\nPreserve evidence; record SHA-256; restrict access.\n',False),('access-policy.txt',b'SECUREVAULT DEMO\nLeast privilege access policy\nReview permissions quarterly.\n',False),('encrypted-notes.txt',b'SECUREVAULT DEMO\nThis sample is encrypted with the demo passphrase.\n',True)]
  for name,data,encrypted in examples:
   fid=uuid.uuid4().hex; path=VAULT/fid
   if encrypted:
    salt=secrets.token_bytes(16); nonce=secrets.token_bytes(12); data=b'SVLT1'+salt+nonce+AESGCM(derive('VaultDemo2026!',salt)).encrypt(nonce,data,None)
   path.write_bytes(data)
   with db() as c: c.execute('INSERT INTO files VALUES(?,?,?,?,?,?,?,?)',(fid,uid,name,fid,len(data), 'text/plain',int(encrypted),now()))
  priv=rsa.generate_private_key(public_exponent=65537,key_size=2048); (KEYS/f'{uid}.private.pem').write_bytes(priv.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())); (KEYS/f'{uid}.public.pem').write_bytes(priv.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
  sample=b'SecureVault demo signature payload'; sig=priv.sign(sample,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); priv.public_key().verify(sig,sample,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
  log(uid,'Hash generated','SHA-256: '+hashlib.sha256(sample).hexdigest()); log(uid,'Signature verified','RSA-PSS sample signature validated successfully.'); log(uid,'Demo data loaded','Sample files and activity are ready.')
 with db() as c: c.execute('UPDATE stats SET logins=logins+1 WHERE owner=?',(uid,))
 log(uid,'Login','Demo session started.'); return {'token':uid,'username':'demo','password':'VaultDemo2026!'}
@app.post('/api/logout')
def logout(x_user:Optional[str]=Header(None)): log(user(x_user),'Logout','Session ended.'); return {'ok':True}
@app.post('/api/password')
def password_change(d:Change,x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: r=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
 if not hmac.compare_digest(derive(d.old_password,r['salt']),r['password_hash']): raise HTTPException(400,'Current password is incorrect.')
 salt=secrets.token_bytes(16)
 with db() as c: c.execute('UPDATE users SET salt=?,password_hash=? WHERE id=?',(salt,derive(d.new_password,salt),uid))
 log(uid,'Password changed','Account password updated.'); return {'ok':True}
@app.get('/api/files')
def files(search:str='',x_user:Optional[str]=Header(None)):
 with db() as c: rows=c.execute('SELECT * FROM files WHERE owner=? AND name LIKE ? ORDER BY created DESC',(user(x_user),f'%{search}%')).fetchall()
 return [entry(r) for r in rows]
@app.post('/api/files')
async def upload(file:UploadFile=File(...),x_user:Optional[str]=Header(None)):
 uid=user(x_user); name=Path(file.filename or 'upload.bin').name; data=await file.read()
 with db() as c:
  if c.execute('SELECT id FROM files WHERE owner=? AND name=?',(uid,name)).fetchone(): raise HTTPException(409,'A file with this name already exists.')
 fid=uuid.uuid4().hex; (VAULT/fid).write_bytes(data)
 with db() as c: c.execute('INSERT INTO files VALUES(?,?,?,?,?,?,?,?)',(fid,uid,name,fid,len(data),file.content_type,0,now()))
 log(uid,'File uploaded',name); return {'id':fid,'name':name}
@app.get('/api/files/{fid}/download')
def download(fid:str,x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: r=c.execute('SELECT * FROM files WHERE id=? AND owner=?',(fid,uid)).fetchone()
 if not r: raise HTTPException(404,'File not found.')
 p=VAULT/r['stored']
 if not p.exists(): raise HTTPException(404,'Stored file is missing.')
 if r['encrypted']: raise HTTPException(400,'Decrypt the file before downloading it.')
 return FileResponse(p,filename=r['name'],media_type=r['mime'])
@app.post('/api/files/{fid}/encrypt')
def encrypt(fid:str,password:str=Form(...),x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: r=c.execute('SELECT * FROM files WHERE id=? AND owner=?',(fid,uid)).fetchone()
 if not r: raise HTTPException(404,'File not found.')
 if r['encrypted']: raise HTTPException(400,'This file is already encrypted.')
 p=VAULT/r['stored']; data=p.read_bytes(); salt=secrets.token_bytes(16); nonce=secrets.token_bytes(12); p.write_bytes(b'SVLT1'+salt+nonce+AESGCM(derive(password,salt)).encrypt(nonce,data,None))
 with db() as c: c.execute('UPDATE files SET encrypted=1 WHERE id=?',(fid,))
 log(uid,'Encryption',r['name']); return {'ok':True}
@app.post('/api/files/{fid}/decrypt')
def decrypt(fid:str,password:str=Form(...),x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: r=c.execute('SELECT * FROM files WHERE id=? AND owner=?',(fid,uid)).fetchone()
 if not r: raise HTTPException(404,'File not found.')
 p=VAULT/r['stored']
 try:
  blob=p.read_bytes()
  if not blob.startswith(b'SVLT1') or len(blob)<33: raise ValueError()
  plain=AESGCM(derive(password,blob[5:21])).decrypt(blob[21:33],blob[33:],None)
 except Exception: raise HTTPException(400,'Password is incorrect or the encrypted file is damaged.')
 p.write_bytes(plain)
 with db() as c: c.execute('UPDATE files SET encrypted=0 WHERE id=?',(fid,)); c.execute('UPDATE stats SET decrypted=decrypted+1 WHERE owner=?',(uid,))
 log(uid,'Decryption',r['name']); return {'ok':True}
@app.patch('/api/files/{fid}')
def rename(fid:str,d:Rename,x_user:Optional[str]=Header(None)):
 uid=user(x_user); name=Path(d.name).name
 with db() as c:
  if not c.execute('SELECT id FROM files WHERE id=? AND owner=?',(fid,uid)).fetchone(): raise HTTPException(404,'File not found.')
  if c.execute('SELECT id FROM files WHERE owner=? AND name=? AND id<>?',(uid,name,fid)).fetchone(): raise HTTPException(409,'A file with this name already exists.')
  c.execute('UPDATE files SET name=? WHERE id=?',(name,fid))
 log(uid,'File renamed',name); return {'ok':True}
@app.delete('/api/files/{fid}')
def delete(fid:str,secure:bool=False,x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: r=c.execute('SELECT * FROM files WHERE id=? AND owner=?',(fid,uid)).fetchone()
 if not r: raise HTTPException(404,'File not found.')
 p=VAULT/r['stored']
 if p.exists():
  if secure:
   try:
    with p.open('r+b') as f: f.write(secrets.token_bytes(p.stat().st_size)); f.flush(); os.fsync(f.fileno())
   except OSError: raise HTTPException(403,'Could not overwrite this file.')
  p.unlink()
 with db() as c: c.execute('DELETE FROM files WHERE id=?',(fid,))
 log(uid,'File deleted',('Securely deleted: ' if secure else 'Deleted: ')+r['name']); return {'ok':True}
def digest(data,a):
 if a.lower() not in ('sha256','sha512','md5'): raise HTTPException(400,'Choose SHA-256, SHA-512, or MD5.')
 return hashlib.new(a.lower(),data).hexdigest()
@app.post('/api/hash/text')
def hash_text(d:TextHash,x_user:Optional[str]=Header(None)):
 uid=user(x_user); value=digest(d.text.encode(),d.algorithm)
 with db() as c: c.execute('UPDATE stats SET hashes=hashes+1 WHERE owner=?',(uid,))
 log(uid,'Hash generated',d.algorithm.upper()+' text digest'); return {'algorithm':d.algorithm.upper(),'hash':value}
@app.post('/api/hash/file')
async def hash_file(file:UploadFile=File(...),algorithm:str=Form('sha256'),x_user:Optional[str]=Header(None)):
 uid=user(x_user); value=digest(await file.read(),algorithm)
 with db() as c: c.execute('UPDATE stats SET hashes=hashes+1 WHERE owner=?',(uid,))
 log(uid,'Hash generated',algorithm.upper()+' file digest'); return {'algorithm':algorithm.upper(),'hash':value}
@app.post('/api/sign/{fid}')
def sign(fid:str,x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: r=c.execute('SELECT * FROM files WHERE id=? AND owner=?',(fid,uid)).fetchone()
 if not r: raise HTTPException(404,'File not found.')
 if r['encrypted']: raise HTTPException(400,'Decrypt the file before signing it.')
 key=KEYS/f'{uid}.private.pem'; pub=KEYS/f'{uid}.public.pem'
 if not key.exists():
  k=rsa.generate_private_key(public_exponent=65537,key_size=2048); key.write_bytes(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())); pub.write_bytes(k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
 k=serialization.load_pem_private_key(key.read_bytes(),None); sig=k.sign((VAULT/r['stored']).read_bytes(),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
 with db() as c: c.execute('UPDATE stats SET signatures=signatures+1 WHERE owner=?',(uid,))
 log(uid,'File signed',r['name']); return {'signature':base64.b64encode(sig).decode(),'public_key':pub.read_text()}
@app.post('/api/verify/{fid}')
def verify(fid:str,d:Verify,x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: r=c.execute('SELECT * FROM files WHERE id=? AND owner=?',(fid,uid)).fetchone()
 if not r: raise HTTPException(404,'File not found.')
 try:
  k=serialization.load_pem_public_key((KEYS/f'{uid}.public.pem').read_bytes()); k.verify(base64.b64decode(d.signature),(VAULT/r['stored']).read_bytes(),padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256()); ok=True
 except Exception: ok=False
 log(uid,'Signature verification','Valid' if ok else 'Invalid'); return {'valid':ok}
@app.post('/api/password-generator')
def generate(d:PwOpts):
 groups=[]
 if d.lowercase: groups.append(string.ascii_lowercase)
 if d.uppercase: groups.append(string.ascii_uppercase)
 if d.numbers: groups.append(string.digits)
 if d.symbols: groups.append('!@#$%^&*()-_=+[]{}:,.?')
 if not groups: raise HTTPException(400,'Select at least one character set.')
 vals=[secrets.choice(g) for g in groups]; pool=''.join(groups); vals += [secrets.choice(pool) for _ in range(d.length-len(vals))]; secrets.SystemRandom().shuffle(vals); return {'password':''.join(vals)}
@app.get('/api/logs')
def logs(search:str='',x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: rows=c.execute('SELECT event,detail,created FROM logs WHERE owner=? AND (event LIKE ? OR detail LIKE ?) ORDER BY id DESC LIMIT 500',(uid,f'%{search}%',f'%{search}%')).fetchall()
 return [dict(r) for r in rows]
@app.get('/api/logs/export')
def export(x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: rows=c.execute('SELECT event,detail,created FROM logs WHERE owner=? ORDER BY id DESC',(uid,)).fetchall()
 s=io.StringIO(); w=csv.writer(s); w.writerow(['Event','Details','Timestamp']); w.writerows([tuple(r) for r in rows]); return StreamingResponse(iter([s.getvalue()]),media_type='text/csv',headers={'Content-Disposition':'attachment; filename=securevault-activity.csv'})
@app.get('/api/dashboard')
def dashboard(x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: rows=c.execute('SELECT * FROM files WHERE owner=?',(uid,)).fetchall(); s=c.execute('SELECT * FROM stats WHERE owner=?',(uid,)).fetchone(); recent=c.execute('SELECT event,detail,created FROM logs WHERE owner=? ORDER BY id DESC LIMIT 6',(uid,)).fetchall()
 return {'total':len(rows),'encrypted':sum(r['encrypted'] for r in rows),'decrypted':s['decrypted'],'storage':sum((VAULT/r['stored']).stat().st_size for r in rows if (VAULT/r['stored']).exists()),'hashes':s['hashes'],'signatures':s['signatures'],'logins':s['logins'],'securityScore':min(100,82+6*int(s['hashes']>0)+7*int(s['signatures']>0)+5*int(bool(rows))),'recent':[dict(r) for r in recent]}
@app.post('/api/backup')
def backup(x_user:Optional[str]=Header(None)):
 uid=user(x_user); target=DATA/f'{uid}-backup.zip'
 with db() as c: rows=c.execute('SELECT * FROM files WHERE owner=?',(uid,)).fetchall()
 with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as archive:
  for row in rows:
   path=VAULT/row['stored']
   if path.is_file(): archive.write(path,row['name'])
 log(uid,'Vault backup','Local archive created.'); return {'ok':True}
@app.get('/api/backup/download')
def backup_download(x_user:Optional[str]=Header(None)):
 uid=user(x_user); p=DATA/f'{uid}-backup.zip'
 if not p.exists(): raise HTTPException(404,'Create a backup first.')
 return FileResponse(p,filename='securevault-backup.zip')
@app.post('/api/backup/restore')
async def backup_restore(file:UploadFile=File(...),x_user:Optional[str]=Header(None)):
 uid=user(x_user); raw=await file.read()
 if len(raw)>256*1024*1024: raise HTTPException(413,'Backup is larger than the 256 MB restore limit.')
 try:
  with zipfile.ZipFile(io.BytesIO(raw)) as archive:
   items=[i for i in archive.infolist() if not i.is_dir()]
   if len(items)>500 or sum(i.file_size for i in items)>512*1024*1024: raise HTTPException(413,'Backup contains too many or too much data to restore.')
   with db() as c: existing={r['name'] for r in c.execute('SELECT name FROM files WHERE owner=?',(uid,)).fetchall()}
   restored=0
   for item in items:
    name=Path(item.filename.replace('\\','/')).name
    if not name or name in ('.','..'): continue
    original=Path(name); candidate=name; suffix=1
    while candidate in existing:
     candidate=f'{original.stem} (restored {suffix}){original.suffix}'; suffix+=1
    existing.add(candidate); data=archive.read(item); fid=uuid.uuid4().hex; (VAULT/fid).write_bytes(data)
    with db() as c: c.execute('INSERT INTO files VALUES(?,?,?,?,?,?,?,?)',(fid,uid,candidate,fid,len(data),mimetypes.guess_type(candidate)[0] or 'application/octet-stream',int(data.startswith(b'SVLT1')),now()))
    restored+=1
 except zipfile.BadZipFile: raise HTTPException(400,'This file is not a valid SecureVault ZIP backup.')
 log(uid,'Vault restored',f'{restored} files restored from backup.'); return {'ok':True,'restored':restored}
@app.delete('/api/vault')
def clear(x_user:Optional[str]=Header(None)):
 uid=user(x_user)
 with db() as c: rows=c.execute('SELECT * FROM files WHERE owner=?',(uid,)).fetchall(); c.execute('DELETE FROM files WHERE owner=?',(uid,))
 for r in rows:
  p=VAULT/r['stored']
  if p.exists(): p.unlink()
 log(uid,'Vault cleared',f'{len(rows)} files removed.'); return {'ok':True}

"""One fixed Python image: bounded TLS acquisition and exact offline engine import.

The meter includes encrypted TLS bytes accepted by acquisition sockets, in both
directions. DNS, TCP/IP headers and kernel retransmissions are outside this
userspace metric. No proxy, credential discovery, transport retry or docker pull.
"""
import argparse,hashlib,io,json,os,re,socket,ssl,stat,subprocess,tarfile,time,urllib.parse,zlib
from pathlib import Path

IMAGE="docker.io/library/python@sha256:f040863673aea2570c3ff6a5c3fb4c673a016cbc5375005ad145915922b6b78a"
MANIFEST=IMAGE.rsplit("@",1)[1]
CONFIG="sha256:4143a73d5a9804c1bb2f93cc823a7c173dbc62964d4a5ccabcb1167229b0e2b9"
HOST="unix:///var/run/docker.sock"
TRANSFER=256*1024**2
UNPACKED=512*1024**2
METADATA=1024**2
ARCHIVE_OVERHEAD=1024**2
STAGING=TRANSFER+UNPACKED*2+METADATA+ARCHIVE_OVERHEAD
REGISTRY="registry-1.docker.io"
AUTH="auth.docker.io"
CDN={"production.cloudflare.docker.com","docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com"}
LAYERS=[("sha256:7fd1ebe418b5079d4aa36f416af9b143d127bc75b0155d71cb5fd559b5e04d39",28249323),("sha256:29a6e787b2e07b2b8a2c88b600812f9f7588374cf74e6f17d696695c8984d900",3342349),("sha256:aded561bdc17f79b65ec824282d38146fac0eb9d8951b9a7a4ca462bbea8c21d",14892797),("sha256:29d8700fe216d98a8d918ecf891265355e2ca697f9c11e8290d00813caaed60d",250)]
MANIFEST_TYPES={"application/vnd.oci.image.manifest.v1+json","application/vnd.docker.distribution.manifest.v2+json"}
CONFIG_TYPES={"application/vnd.oci.image.config.v1+json","application/vnd.docker.container.image.v1+json"}
LAYER_TYPES={"application/vnd.oci.image.layer.v1.tar+gzip","application/vnd.docker.image.rootfs.diff.tar.gzip"}

class ImageFailure(RuntimeError):pass
def need(value,code):
 if not value:raise ImageFailure(code)
def digest(data):return "sha256:"+hashlib.sha256(data).hexdigest()
def unique(pairs):
 value={}
 for key,item in pairs:need(key not in value,"IMAGE_JSON_DUPLICATE_KEY");value[key]=item
 return value
def document(data):
 try:return json.loads(data,object_pairs_hook=unique)
 except(ValueError,UnicodeError):raise ImageFailure("IMAGE_JSON_INVALID")from None
def check_time(end):need(time.monotonic()<end,"IMAGE_DEADLINE_EXHAUSTED")

class Meter:
 def __init__(self,end,cap=TRANSFER):self.end=end;self.cap=cap;self.sent=0;self.received=0;self.requests=0
 def available(self):
  check_time(self.end);left=self.cap-self.sent-self.received;need(left>0,"IMAGE_TLS_TRANSFER_LIMIT");return left
 def send(self,sock,data):
  while data:
   left=self.available();sock.settimeout(min(5,self.end-time.monotonic()));size=sock.send(data[:left]);need(0<size<=min(len(data),left),"IMAGE_TRANSPORT_CLOSED");self.sent+=size;data=data[size:]
 def recv(self,sock):
  left=self.available();sock.settimeout(min(5,self.end-time.monotonic()));data=sock.recv(min(16384,left));self.received+=len(data);return data
 def facts(self):return {"metric":"encrypted TLS socket bytes sent plus received; excludes DNS/TCP/IP/kernel retransmissions","sentBytes":self.sent,"receivedBytes":self.received,"totalBytes":self.sent+self.received,"maximumBytes":self.cap,"requests":self.requests,"maximumRequests":24,"transportRetries":0}

class TLS:
 def __init__(self,host,meter):
  self.m=meter;self.sock=None;self.buffer=bytearray()
  try:
   # create_connection silently tries subsequent addresses on connection
   # failure. Choose one IPv4 result explicitly; no hidden transport retry.
   meter.available();addresses=socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP)
   need(0<len(addresses)<=32,"IMAGE_DNS_RESULT_INVALID");family,kind,protocol,_,address=addresses[0]
   need(family==socket.AF_INET and kind==socket.SOCK_STREAM and protocol==socket.IPPROTO_TCP and len(address)==2 and address[1]==443,"IMAGE_DNS_RESULT_INVALID")
   meter.available();self.sock=socket.socket(family,kind,protocol);self.sock.settimeout(min(5,meter.end-time.monotonic()));self.sock.connect(address)
   context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2;context.set_alpn_protocols(["http/1.1"])
   self.incoming,self.outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
   self.tls=context.wrap_bio(self.incoming,self.outgoing,server_hostname=host)
   self.action(self.tls.do_handshake)
   need(self.tls.selected_alpn_protocol()in(None,"http/1.1"),"IMAGE_HTTP_PROTOCOL_UNSUPPORTED")
  except BaseException:
   self.close();raise
 def flush(self):
  while self.outgoing.pending:self.m.send(self.sock,self.outgoing.read(min(16384,self.outgoing.pending)))
 def action(self,fn):
  while True:
   self.m.available()
   try:result=fn();self.flush();return result
   except ssl.SSLWantWriteError:self.flush()
   except ssl.SSLWantReadError:
    self.flush();chunk=self.m.recv(self.sock)
    if not chunk:self.incoming.write_eof();raise ImageFailure("IMAGE_TLS_PREMATURE_EOF")
    self.incoming.write(chunk)
 def write(self,data):
  while data:
   size=self.action(lambda:self.tls.write(data[:16384]));need(size>0,"IMAGE_TLS_WRITE_FAILED");data=data[size:]
 def read(self,n):
  while len(self.buffer)<n:
   data=self.action(lambda:self.tls.read(min(16384,n-len(self.buffer))))
   need(data,"IMAGE_HTTP_PREMATURE_EOF");self.buffer.extend(data)
  result=bytes(self.buffer[:n]);del self.buffer[:n];return result
 def line(self,cap):
  value=bytearray()
  while not value.endswith(b"\r\n"):
   need(len(value)<cap,"IMAGE_HTTP_LINE_LIMIT");value.extend(self.read(1))
  return bytes(value)
 def close(self):
  if self.sock:self.sock.close();self.sock=None

def url_target(url,kind,object_digest):
 parsed=urllib.parse.urlsplit(url)
 need(parsed.scheme=="https"and parsed.port in(None,443)and parsed.username is None and parsed.password is None and not parsed.fragment and len(url)<=8192 and url.isascii(),"IMAGE_REGISTRY_URL_REFUSED")
 host=parsed.hostname;path=parsed.path;query=parsed.query
 if host==REGISTRY:
  need(not query and path==f"/v2/library/python/{'manifests'if kind=='manifest'else'blobs'}/{object_digest}","IMAGE_REGISTRY_PATH_REFUSED")
 elif host in CDN:
  hex_digest=object_digest.removeprefix("sha256:")
  need(kind=="blob"and path.endswith(f"/docker/registry/v2/blobs/sha256/{hex_digest[:2]}/{hex_digest}/data"),"IMAGE_CDN_PATH_REFUSED")
 elif host==AUTH:
  need(kind=="auth"and path=="/token"and urllib.parse.parse_qs(query)=={"service":["registry.docker.io"],"scope":["repository:library/python:pull"]},"IMAGE_AUTH_SCOPE_REFUSED")
 else:raise ImageFailure("IMAGE_REGISTRY_REDIRECT_HOST_REFUSED")
 target=path+("?"+query if query else"")
 need("\r"not in target and"\n"not in target,"IMAGE_HTTP_REQUEST_REFUSED")
 return host,target

def request(url,kind,object_digest,meter,token,maximum,sink):
 host,target=url_target(url,kind,object_digest);meter.requests+=1;need(meter.requests<=24,"IMAGE_HTTP_REQUEST_LIMIT")
 stream=TLS(host,meter)
 try:
  headers=[f"GET {target} HTTP/1.1",f"Host: {host}","Connection: close","Accept-Encoding: identity","Accept: "+", ".join(sorted(MANIFEST_TYPES))]
  if host==REGISTRY and token:headers.append("Authorization: Bearer "+token)
  stream.write(("\r\n".join(headers)+"\r\n\r\n").encode("ascii"))
  status=stream.line(4096);match=re.fullmatch(rb"HTTP/1\.[01] ([0-9]{3}) [^\r\n]*\r\n",status);need(match,"IMAGE_HTTP_STATUS_INVALID")
  code=int(match[1]);values={};header_bytes=len(status)
  for i in range(101):
   line=stream.line(8192);header_bytes+=len(line);need(header_bytes<=65536,"IMAGE_HTTP_HEADER_LIMIT")
   if line==b"\r\n":break
   need(i<100 and b":"in line and not line.startswith((b" ",b"\t")),"IMAGE_HTTP_HEADER_INVALID")
   key,raw=line[:-2].split(b":",1);need(re.fullmatch(rb"[A-Za-z0-9-]+",key),"IMAGE_HTTP_HEADER_INVALID")
   key=key.decode().lower();need(key not in values,"IMAGE_HTTP_DUPLICATE_HEADER");values[key]=raw.strip().decode("latin1")
  else:raise ImageFailure("IMAGE_HTTP_HEADER_LIMIT")
  need(values.get("content-encoding","identity")=="identity","IMAGE_HTTP_ENCODING_REFUSED")
  if code in(301,302,303,307,308,401):return code,values,0
  need(code==200,"IMAGE_REGISTRY_HTTP_FAILURE")
  length=values.get("content-length");encoding=values.get("transfer-encoding");total=0
  need(not(length is not None and encoding is not None),"IMAGE_HTTP_FRAMING_INVALID")
  def accept(data):
   nonlocal total
   total+=len(data);need(total<=maximum,"IMAGE_RESPONSE_SIZE_LIMIT");sink(data)
  if length is not None:
   need(length.isdecimal()and int(length)<=maximum,"IMAGE_RESPONSE_SIZE_LIMIT")
   left=int(length)
   while left:chunk=stream.read(min(65536,left));accept(chunk);left-=len(chunk)
  else:
   need(encoding=="chunked","IMAGE_HTTP_FRAMING_UNSUPPORTED")
   while True:
    line=stream.line(32);need(re.fullmatch(rb"[0-9A-Fa-f]{1,16}\r\n",line),"IMAGE_HTTP_CHUNK_INVALID");size=int(line[:-2],16)
    if not size:need(stream.line(2)==b"\r\n","IMAGE_HTTP_TRAILER_REFUSED");break
    need(size<=maximum-total,"IMAGE_RESPONSE_SIZE_LIMIT")
    while size:chunk=stream.read(min(65536,size));accept(chunk);size-=len(chunk)
    need(stream.read(2)==b"\r\n","IMAGE_HTTP_CHUNK_INVALID")
  return code,values,total
 finally:stream.close()

class Registry:
 def __init__(self,meter):self.m=meter;self.token=None
 def fetch(self,kind,object_digest,maximum,sink):
  initial=f"https://{REGISTRY}/v2/library/python/{'manifests'if kind=='manifest'else'blobs'}/{object_digest}";url=initial;redirects=0;challenge=False
  while True:
   code,headers,size=request(url,kind,object_digest,self.m,self.token,maximum,sink)
   if code==200:return size
   if code==401:
    need(url==initial and not challenge and self.token is None,"IMAGE_AUTH_CHALLENGE_REFUSED");challenge=True
    auth=headers.get("www-authenticate","")
    need(auth.startswith("Bearer "),"IMAGE_AUTH_CHALLENGE_REFUSED")
    pairs=re.findall(r'([A-Za-z]+)="([^"\\\r\n]*)"',auth[7:])
    need(re.fullmatch(r'[A-Za-z]+="[^"\\\r\n]*"(?:,\s*[A-Za-z]+="[^"\\\r\n]*")*',auth[7:])and len(pairs)==3 and len(dict(pairs))==3 and dict(pairs)=={"realm":"https://auth.docker.io/token","service":"registry.docker.io","scope":"repository:library/python:pull"},"IMAGE_AUTH_CHALLENGE_REFUSED")
    chunks=[];auth_url="https://auth.docker.io/token?"+urllib.parse.urlencode({"service":"registry.docker.io","scope":"repository:library/python:pull"})
    status,_,_=request(auth_url,"auth",object_digest,self.m,None,65536,chunks.append);need(status==200,"IMAGE_AUTH_HTTP_FAILURE")
    value=document(b"".join(chunks));token=value.get("token",value.get("access_token"))if isinstance(value,dict)else None
    need(isinstance(value,dict)and ("access_token"not in value or value["access_token"]==token),"IMAGE_AUTH_TOKEN_INVALID")
    need(isinstance(token,str)and 16<=len(token)<=16384 and re.fullmatch(r"[A-Za-z0-9._~-]+",token),"IMAGE_AUTH_TOKEN_INVALID");self.token=token;continue
   redirects+=1;need(redirects<=2 and kind=="blob","IMAGE_REDIRECT_LIMIT");url=headers.get("location","");url_target(url,kind,object_digest)

def descriptor(value,types,expected=None):
 need(isinstance(value,dict)and value.get("mediaType")in types and type(value.get("size"))is int and 0<value["size"]<=TRANSFER and isinstance(value.get("digest"),str)and re.fullmatch(r"sha256:[a-f0-9]{64}",value["digest"]),"IMAGE_DESCRIPTOR_INVALID")
 if expected:need((value["digest"],value["size"])==expected,"IMAGE_LAYER_PIN_DIFFERS")
 return value

def verified_metadata(registry):
 chunks=[];registry.fetch("manifest",MANIFEST,METADATA,chunks.append);raw=b"".join(chunks);need(digest(raw)==MANIFEST,"IMAGE_MANIFEST_DIGEST_DIFFERS");manifest=document(raw)
 need(isinstance(manifest,dict)and manifest.get("schemaVersion")==2 and manifest.get("mediaType")in MANIFEST_TYPES,"IMAGE_MANIFEST_INVALID")
 config=descriptor(manifest.get("config"),CONFIG_TYPES);need(config["digest"]==CONFIG and config["size"]<=METADATA,"IMAGE_CONFIG_PIN_DIFFERS")
 layers=manifest.get("layers");need(isinstance(layers,list)and len(layers)==len(LAYERS),"IMAGE_LAYER_COUNT_DIFFERS")
 for value,want in zip(layers,LAYERS):descriptor(value,LAYER_TYPES,want)
 need(sum(x["size"]for x in layers)+config["size"]+len(raw)<=TRANSFER,"IMAGE_DECLARED_TRANSFER_LIMIT")
 chunks=[];size=registry.fetch("blob",CONFIG,config["size"],chunks.append);config_raw=b"".join(chunks);need(size==config["size"]and digest(config_raw)==CONFIG,"IMAGE_CONFIG_DIGEST_DIFFERS");data=document(config_raw)
 need(isinstance(data,dict)and data.get("os")=="linux"and data.get("architecture")=="amd64"and isinstance(data.get("rootfs"),dict),"IMAGE_PLATFORM_DIFFERS")
 diff=data["rootfs"].get("diff_ids");need(data["rootfs"].get("type")=="layers"and isinstance(diff,list)and len(diff)==len(layers)and all(isinstance(x,str)and re.fullmatch(r"sha256:[a-f0-9]{64}",x)for x in diff),"IMAGE_ROOTFS_INVALID")
 need(isinstance(data.get("config"),dict)and not data["config"].get("Volumes"),"IMAGE_VOLUMES_REFUSED")
 return config_raw,layers,diff

def unpack_layer(source,target,want,total,end,cap=UNPACKED):
 decoder=zlib.decompressobj(16+zlib.MAX_WBITS);hash_=hashlib.sha256()
 with source.open("rb")as compressed,target.open("xb")as output:
  while chunk:=compressed.read(65536):
   check_time(end);need(not decoder.eof,"IMAGE_GZIP_TRAILING_DATA")
   while chunk:
    data=decoder.decompress(chunk,min(65536,max(1,cap-total+1)));chunk=decoder.unconsumed_tail
    need(total+len(data)<=cap,"IMAGE_UNPACKED_LIMIT");output.write(data);hash_.update(data);total+=len(data)
    need(not decoder.unused_data,"IMAGE_GZIP_TRAILING_DATA")
  need(decoder.eof,"IMAGE_GZIP_INCOMPLETE")
 need("sha256:"+hash_.hexdigest()==want,"IMAGE_DIFF_ID_DIFFERS")
 return total

def prepare_archive(registry,staging,config,layers,diffs,end):
 total=0;paths=[]
 for i,(value,want)in enumerate(zip(layers,diffs)):
  compressed=staging/f"{i}.gzip";hash_=hashlib.sha256()
  with compressed.open("xb")as output:
   def sink(data):check_time(end);output.write(data);hash_.update(data)
   size=registry.fetch("blob",value["digest"],value["size"],sink)
  need(size==value["size"]and "sha256:"+hash_.hexdigest()==value["digest"],"IMAGE_LAYER_DIGEST_DIFFERS")
  layer=staging/f"{i}.tar";total=unpack_layer(compressed,layer,want,total,end);paths.append(layer)
 archive=staging/"image.tar";names=[f"{i}/layer.tar"for i in range(len(paths))];configuration=CONFIG.removeprefix("sha256:")+".json"
 with tarfile.open(archive,"x",format=tarfile.USTAR_FORMAT)as output:
  def add(name,data):
   check_time(end);header=tarfile.TarInfo(name);header.size=len(data);header.mode=0o600;output.addfile(header,io.BytesIO(data))
  add(configuration,config);add("manifest.json",json.dumps([{"Config":configuration,"RepoTags":[],"Layers":names}],separators=(",",":")).encode())
  for name,source in zip(names,paths):
   check_time(end);header=tarfile.TarInfo(name);header.size=source.stat().st_size;header.mode=0o600
   class TimedReader:
    def __init__(self,source):self.source=source
    def read(self,size):check_time(end);return self.source.read(size)
   with source.open("rb")as data:output.addfile(header,TimedReader(data))
 need(archive.stat().st_size<=total+len(config)+ARCHIVE_OVERHEAD,"IMAGE_ARCHIVE_LIMIT")
 need(sum(x.stat().st_size for x in staging.iterdir())<=STAGING,"IMAGE_STAGING_LIMIT")
 return archive,total

def save(path,value):
 temporary=path.with_suffix(".writing");need(not temporary.exists(),"IMAGE_LEDGER_WRITE_CUSTODY_UNKNOWN")
 with temporary.open("x")as output:os.chmod(temporary,0o600);json.dump(value,output);output.flush();os.fsync(output.fileno())
 os.replace(temporary,path)
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)

def socket_identity(socket_mark):
 path=Path("/var/run/docker.sock").resolve(strict=True);st=path.stat();need((st.st_dev,st.st_ino)==socket_mark and stat.S_ISSOCK(st.st_mode),"IMAGE_ENGINE_SOCKET_CHANGED")

def engine(args,end,expected_engine,socket_mark):
 socket_identity(socket_mark)
 check_time(end)
 result=subprocess.run(["docker","--host",HOST,*args],capture_output=True,timeout=min(5,end-time.monotonic()))
 need(not result.returncode and not result.stderr and len(result.stdout)<=65536,"IMAGE_ENGINE_OBSERVATION_FAILED")
 socket_identity(socket_mark)
 return result.stdout

def import_archive(archive,end,expected_engine,socket_mark):
 # Issued custody is durable before this wrapper. Re-resolve the actual CLI
 # endpoint around the mutation; post-check failure remains held, never retry.
 need(engine(["info","--format","{{.ID}}"],end,expected_engine,socket_mark).decode().strip()==expected_engine,"IMAGE_ENGINE_ID_CHANGED")
 socket_identity(socket_mark);check_time(end)
 result=subprocess.run(["docker","--host",HOST,"image","load","--input",str(archive),"--quiet"],capture_output=True,timeout=min(20,end-time.monotonic()))
 socket_identity(socket_mark)
 need(not result.returncode and not result.stderr and len(result.stdout)<=65536,"IMAGE_IMPORT_UNCERTAIN")
 need(engine(["info","--format","{{.ID}}"],end,expected_engine,socket_mark).decode().strip()==expected_engine,"IMAGE_ENGINE_ID_CHANGED")

def image_ids(observe):
 ids=observe(["image","ls","--all","--no-trunc","--format","{{.ID}}"],False).decode().splitlines()
 need(len(ids)<=512 and all(re.fullmatch(r"sha256:[a-f0-9]{64}",x)for x in ids),"IMAGE_CENSUS_INVALID");return set(ids)
def check_image(observe,diffs):
 values=document(observe(["image","inspect",CONFIG],False));need(isinstance(values,list)and len(values)==1,"IMAGE_IMPORT_IDENTITY_UNAVAILABLE");value=values[0]
 need(isinstance(value,dict)and value.get("Id")==CONFIG and value.get("Os")=="linux"and value.get("Architecture")=="amd64"and isinstance(value.get("RootFS"),dict)and value["RootFS"].get("Layers")==diffs and isinstance(value.get("Config"),dict)and type(value.get("Size"))is int and 0<value["Size"]<=UNPACKED and not value["Config"].get("Volumes"),"IMAGE_IMPORT_IDENTITY_DIFFERS")
 return value["Size"]

def acquire(state,staging,end,expected_engine,socket_mark,registry=None,observe=None,load=None):
 need(not state.exists()and not staging.exists(),"IMAGE_PREPARATION_REPLAY_REFUSED");staging.mkdir(mode=0o700);need(staging.resolve()==staging,"IMAGE_STAGING_ALIAS_REFUSED")
 meter=Meter(end-45);registry=registry or Registry(meter)
 if hasattr(registry,"m"):registry.m=meter
 def read_engine(args,identity=True):
  if identity:need(engine(["info","--format","{{.ID}}"],end,expected_engine,socket_mark).decode().strip()==expected_engine,"IMAGE_ENGINE_ID_CHANGED")
  return engine(args,end,expected_engine,socket_mark)
 observe=observe or read_engine
 value={"format":1,"phase":"prepared","issued":False,"engineId":expected_engine,"image":IMAGE,"runtimeImage":CONFIG,"staging":str(staging),"socketDevice":socket_mark[0],"socketInode":socket_mark[1]};save(state,value)
 try:
  need(observe(["info","--format","{{.ID}}"],False).decode().strip()==expected_engine,"IMAGE_ENGINE_ID_CHANGED")
  present=CONFIG in image_ids(observe);config,layers,diffs=verified_metadata(registry);value.update(registryOriginVerified=True,rootfs=diffs)
  if not present:
   archive,unpacked=prepare_archive(registry,staging,config,layers,diffs,meter.end);value.update(unpackedLayerTarBytes=unpacked,archiveBytes=archive.stat().st_size)
   present=CONFIG in image_ids(observe)
   if not present:
    check_time(end-40);need(observe(["info","--format","{{.ID}}"],False).decode().strip()==expected_engine,"IMAGE_ENGINE_ID_CHANGED")
    value.update(phase="import-issued",issued=True);save(state,value)
    if load:load(archive,end)
    else:import_archive(archive,end,expected_engine,socket_mark)
  need(observe(["info","--format","{{.ID}}"],False).decode().strip()==expected_engine,"IMAGE_ENGINE_ID_CHANGED")
  image_size=check_image(observe,diffs)
  need(observe(["info","--format","{{.ID}}"],False).decode().strip()==expected_engine,"IMAGE_ENGINE_ID_CHANGED");check_time(end)
  value.update(phase="confirmed",imageSizeBytes=image_size,preexisting=present,imported=not present,imageDisposition="retained-and-accounted-for-ephemeral-runner-teardown; no exclusive ownership or removal claim",transport=meter.facts());save(state,value)
  return value
 except BaseException as error:
  value.update(phase="held"if value["issued"]else"failed-before-import",failure=str(error)if isinstance(error,ImageFailure)else"IMAGE_PREPARATION_FAILED",transport=meter.facts());save(state,value)
  raise ImageFailure(value["failure"])from None

def main():
 parser=argparse.ArgumentParser();parser.add_argument("--state",type=Path,required=True);parser.add_argument("--staging",type=Path,required=True);parser.add_argument("--engine-id",required=True);parser.add_argument("--socket-device",type=int,required=True);parser.add_argument("--socket-inode",type=int,required=True);args=parser.parse_args()
 try:
  end=time.monotonic()+min(90,max(0,int(os.environ["OPENCLAW_NATIVE_IMAGE_END_MS"])/1000-time.time()));acquire(args.state,args.staging,end,args.engine_id,(args.socket_device,args.socket_inode));print("Pinned image preparation confirmed; private custody retained locally.");return 0
 except BaseException as error:print(str(error)if isinstance(error,ImageFailure)else"IMAGE_PREPARATION_FAILED");return 1

if __name__=="__main__":raise SystemExit(main())

"""Offline acquisition contracts. All network and engine APIs are injected."""
import ast,gzip,hashlib,io,json,os,socket,ssl,subprocess,tarfile,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
import native_image as image
import native
from test_native import NativeFixture,HERE

class RawSocket:
 def __init__(self,data=b"",step=3):self.data=data;self.step=step;self.sent=bytearray();self.closed=False;self.sizes=[]
 def settimeout(self,value):assert 0<value<=5
 def send(self,data):size=min(len(data),self.step);self.sent.extend(data[:size]);return size
 def recv(self,size):self.sizes.append(size);result=self.data[:size];self.data=self.data[size:];return result
 def close(self):self.closed=True

class WireMeterTests(unittest.TestCase):
 def test_connection_uses_one_ipv4_result_without_hidden_address_fallback(self):
  addresses=[(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,"",("192.0.2.1",443)),(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,"",("192.0.2.2",443))];sock=Mock();sock.connect.side_effect=socket.timeout("not public")
  with patch.object(socket,"getaddrinfo",return_value=addresses)as dns,patch.object(socket,"socket",return_value=sock)as create:
   with self.assertRaises(socket.timeout):image.TLS(image.REGISTRY,image.Meter(time.monotonic()+10))
   dns.assert_called_once_with(image.REGISTRY,443,socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP);create.assert_called_once();sock.connect.assert_called_once_with(("192.0.2.1",443));sock.close.assert_called_once()
 def test_partial_sends_and_receives_share_one_pre_enforced_cap(self):
  meter=image.Meter(time.monotonic()+10,10);sock=RawSocket(b"12345678")
  meter.send(sock,b"abcdef");self.assertEqual(meter.recv(sock),b"1234")
  with self.assertRaisesRegex(image.ImageFailure,"TLS_TRANSFER_LIMIT"):meter.recv(sock)
  self.assertEqual((meter.sent,meter.received,sock.sizes),(6,4,[4]));self.assertEqual(meter.facts()["totalBytes"],10)
 def test_cap_exhausted_mid_send_retains_actual_partial_bytes(self):
  meter=image.Meter(time.monotonic()+10,4);sock=RawSocket()
  with self.assertRaisesRegex(image.ImageFailure,"TLS_TRANSFER_LIMIT"):meter.send(sock,b"abcdefgh")
  self.assertEqual(bytes(sock.sent),b"abcd");self.assertEqual(meter.sent,4)
 def test_expired_budget_refuses_before_socket_io(self):
  meter=image.Meter(time.monotonic()-1);sock=RawSocket()
  with self.assertRaisesRegex(image.ImageFailure,"DEADLINE"):meter.send(sock,b"x")
  self.assertFalse(sock.sent)
 def test_tls_handshake_error_and_request_bytes_use_same_socket_meter(self):
  meter=image.Meter(time.monotonic()+10,30);sock=RawSocket(b"server-error",step=20)
  outgoing=ssl.MemoryBIO();incoming=ssl.MemoryBIO();outgoing.write(b"client-hello")
  tls=object.__new__(image.TLS);tls.m=meter;tls.sock=sock;tls.outgoing=outgoing;tls.incoming=incoming
  def handshake():
   if not incoming.pending:raise ssl.SSLWantReadError()
   raise image.ImageFailure("TEST_TLS_CERTIFICATE_FAILURE")
  with self.assertRaisesRegex(image.ImageFailure,"CERTIFICATE"):tls.action(handshake)
  self.assertEqual((meter.sent,meter.received),(12,12));self.assertIn("excludes DNS",meter.facts()["metric"])

class URLAndHTTPTests(unittest.TestCase):
 def setUp(self):self.end=time.monotonic()+10
 def test_fixed_pin_registry_auth_and_cdn_paths(self):
  digest=image.LAYERS[0][0];hex_=digest[7:]
  url=f"https://production.cloudflare.docker.com/registry-v2/docker/registry/v2/blobs/sha256/{hex_[:2]}/{hex_}/data?private=signature"
  self.assertEqual(image.url_target(url,"blob",digest)[0],"production.cloudflare.docker.com")
  for bad in("http://registry-1.docker.io/", "https://user:secret@registry-1.docker.io/", "https://registry-1.docker.io:8443/",url.replace(hex_,"0"*64),url.replace("production.cloudflare.docker.com","unreviewed.example")):
   with self.subTest(url=bad),self.assertRaises(image.ImageFailure):image.url_target(bad,"blob",digest)
  with self.assertRaises(image.ImageFailure):image.url_target("https://auth.docker.io/token?service=registry.docker.io&scope=repository:foreign:pull","auth",digest)
 def http(self,response,url=None,token="PRIVATE_TOKEN",maximum=4):
  holder=[]
  class FakeTLS:
   def __init__(self,host,meter):self.input=io.BytesIO(response);self.written=b"";self.closed=False;holder.append(self)
   def write(self,data):self.written+=data
   def read(self,n):data=self.input.read(n);image.need(len(data)==n,"IMAGE_HTTP_PREMATURE_EOF");return data
   def line(self,cap):data=self.input.readline(cap);image.need(data.endswith(b"\r\n"),"IMAGE_HTTP_LINE_LIMIT");return data
   def close(self):self.closed=True
  url=url or f"https://{image.REGISTRY}/v2/library/python/blobs/{image.CONFIG}"
  sink=[]
  with patch.object(image,"TLS",FakeTLS):result=image.request(url,"blob",image.CONFIG,image.Meter(self.end),token,maximum,sink.append)
  return result,b"".join(sink),holder[0]
 def test_content_length_enforced_before_body_sink(self):
  with self.assertRaisesRegex(image.ImageFailure,"RESPONSE_SIZE_LIMIT"):self.http(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n12345")
  result,data,stream=self.http(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n1234")
  self.assertEqual((result[0],data),(200,b"1234"));self.assertTrue(stream.closed)
 def test_chunked_cap_duplicate_and_conflicting_framing_refuse(self):
  for raw,code in((b"Transfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n","RESPONSE_SIZE_LIMIT"),(b"Content-Length: 0\r\nContent-Length: 0\r\n\r\n","DUPLICATE_HEADER"),(b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n","FRAMING_INVALID")):
   with self.subTest(code=code),self.assertRaisesRegex(image.ImageFailure,code):self.http(b"HTTP/1.1 200 OK\r\n"+raw)
  _,data,_=self.http(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n")
  self.assertEqual(data,b"abcd")
 def test_registry_bearer_is_never_forwarded_to_cdn(self):
  hex_=image.CONFIG[7:];url=f"https://production.cloudflare.docker.com/docker/registry/v2/blobs/sha256/{hex_[:2]}/{hex_}/data?private=signed"
  _,_,cdn=self.http(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",url=url)
  self.assertNotIn(b"Authorization",cdn.written);self.assertNotIn(b"PRIVATE_TOKEN",cdn.written)
  _,_,registry=self.http(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
  self.assertIn(b"Authorization: Bearer PRIVATE_TOKEN",registry.written)
 def test_transport_failure_has_no_retry(self):
  registry=image.Registry(image.Meter(self.end))
  with patch.object(image,"request",side_effect=socket.timeout("PRIVATE_SIGNED_URL"))as request:
   with self.assertRaises(socket.timeout):registry.fetch("manifest",image.MANIFEST,4,lambda data:None)
  self.assertEqual(request.call_count,1)
 def test_exact_challenge_allows_parameter_order_but_refuses_scope_changes(self):
  registry=image.Registry(image.Meter(self.end));calls=[]
  def request(url,kind,digest,meter,token,maximum,sink):
   calls.append((kind,token))
   if len(calls)==1:return 401,{"www-authenticate":'Bearer scope="repository:library/python:pull", realm="https://auth.docker.io/token",service="registry.docker.io"'},0
   if kind=="auth":sink(json.dumps({"token":"x"*20,"access_token":"x"*20}).encode());return 200,{},1
   return 200,{},0
  with patch.object(image,"request",request):registry.fetch("manifest",image.MANIFEST,4,lambda data:None)
  self.assertEqual(calls,[("manifest",None),("auth",None),("manifest","x"*20)])
  registry=image.Registry(image.Meter(self.end))
  with patch.object(image,"request",return_value=(401,{"www-authenticate":'Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:foreign:pull"'},0))as call:
   with self.assertRaisesRegex(image.ImageFailure,"CHALLENGE_REFUSED"):registry.fetch("manifest",image.MANIFEST,4,lambda data:None)
   self.assertEqual(call.call_count,1)
 def test_redirects_are_bounded_and_unreviewed_host_refuses_without_contact(self):
  registry=image.Registry(image.Meter(self.end))
  with patch.object(image,"request",return_value=(307,{"location":"https://unreviewed.example/private-signed"},0))as call:
   with self.assertRaisesRegex(image.ImageFailure,"REDIRECT_HOST_REFUSED"):registry.fetch("blob",image.CONFIG,4,lambda data:None)
   self.assertEqual(call.call_count,1)

class TinyRegistry:
 def __init__(self,values):self.values=values;self.calls=[];self.m=None
 def fetch(self,kind,digest,maximum,sink):
  raw=self.values[digest];self.calls.append((kind,digest));image.need(len(raw)<=maximum,"IMAGE_RESPONSE_SIZE_LIMIT");sink(raw);return len(raw)

class ImagePreparationTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve();self.state=self.root/"state.json";self.stage=self.root/"stage";self.end=time.monotonic()+90
  raw=b"opaque layer tar bytes";compressed=gzip.compress(raw,mtime=0);self.diffs=[image.digest(raw)]
  config=json.dumps({"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":self.diffs},"config":{}},separators=(",",":")).encode();config_id=image.digest(config)
  layers=[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":image.digest(compressed),"size":len(compressed)}]
  manifest=json.dumps({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":config_id,"size":len(config)},"layers":layers},separators=(",",":")).encode()
  self.registry=TinyRegistry({image.digest(manifest):manifest,config_id:config,layers[0]["digest"]:compressed});self.config=config;self.layers=layers;self.present=False;self.loaded=0
  for name,value in(("CONFIG",config_id),("MANIFEST",image.digest(manifest)),("LAYERS",[(layers[0]["digest"],len(compressed))])):
   patcher=patch.object(image,name,value);patcher.start();self.addCleanup(patcher.stop)
 def observe(self,args,identity=False):
  if args[:1]==["info"]:return b"engine-one\n"
  if args[:2]==["image","ls"]:return (image.CONFIG+"\n").encode()if self.present else b""
  if args[:2]==["image","inspect"]:return json.dumps([{"Id":image.CONFIG,"Os":"linux","Architecture":"amd64","RootFS":{"Layers":self.diffs},"Config":{},"Size":123}]).encode()
  self.fail("unexpected observation "+str(args))
 def load(self,archive,end):
  value=json.loads(self.state.read_text());self.assertEqual((value["phase"],value["issued"]),("import-issued",True));self.loaded+=1;self.present=True
  with tarfile.open(archive)as source:
   manifest=json.load(source.extractfile("manifest.json"));self.assertEqual(manifest[0]["RepoTags"],[])
   self.assertEqual(source.extractfile(manifest[0]["Config"]).read(),self.config);self.assertEqual(source.extractfile(manifest[0]["Layers"][0]).read(),b"opaque layer tar bytes")
 def acquire(self,**kwargs):return image.acquire(self.state,self.stage,self.end,"engine-one",(1,2),registry=self.registry,observe=kwargs.get("observe",self.observe),load=kwargs.get("load",self.load))
 def test_missing_image_import_is_once_and_exact_config_identity_preserves_digest_origin(self):
  value=self.acquire();self.assertEqual(self.loaded,1);self.assertEqual((value["phase"],value["imported"],value["runtimeImage"]),("confirmed",True,image.CONFIG));self.assertEqual(value["image"],image.IMAGE)
  self.assertEqual(self.state.stat().st_mode&0o777,0o600);self.assertEqual(self.stage.stat().st_mode&0o777,0o700)
  with self.assertRaisesRegex(image.ImageFailure,"REPLAY_REFUSED"):self.acquire()
  self.assertEqual(self.loaded,1)
 def test_preexisting_config_still_verifies_registry_manifest_and_never_imports(self):
  self.present=True;value=self.acquire();self.assertEqual(self.loaded,0);self.assertTrue(value["preexisting"])
  self.assertEqual([x[0]for x in self.registry.calls],["manifest","blob"]);self.assertFalse((self.stage/"image.tar").exists())
 def test_concurrent_image_appearance_is_retained_without_ownership_or_deletion_claim(self):
  count=0
  def observe(args,identity=False):
   nonlocal count
   if args[:2]==["image","ls"]:count+=1;self.present=count>=2
   return self.observe(args,identity)
  value=self.acquire(observe=observe);self.assertEqual(self.loaded,0);self.assertTrue(value["preexisting"]);self.assertIn("no exclusive ownership",value["imageDisposition"])
 def test_uncertain_import_retains_issued_custody_and_never_retries(self):
  def load(archive,end):self.loaded+=1;self.assertTrue(json.loads(self.state.read_text())["issued"]);raise subprocess.TimeoutExpired("private archive",25)
  with self.assertRaisesRegex(image.ImageFailure,"PREPARATION_FAILED"):self.acquire(load=load)
  value=json.loads(self.state.read_text());self.assertEqual((value["phase"],value["issued"]),("held",True));self.assertTrue((self.stage/"image.tar").exists())
  with self.assertRaisesRegex(image.ImageFailure,"REPLAY_REFUSED"):self.acquire(load=load)
  self.assertEqual(self.loaded,1);self.assertNotIn("private archive",json.dumps(value))
 def test_before_import_failure_preserves_transfer_counters_and_safe_categorical_error(self):
  def fetch(kind,digest,maximum,sink):self.registry.m.sent=2;self.registry.m.received=3;raise socket.timeout("SECRET_URL")
  self.registry.fetch=fetch
  with self.assertRaisesRegex(image.ImageFailure,"PREPARATION_FAILED"):self.acquire()
  value=json.loads(self.state.read_text());self.assertEqual((value["phase"],value["issued"]),("failed-before-import",False));self.assertEqual(value["transport"]["totalBytes"],5);self.assertNotIn("SECRET",json.dumps(value));self.assertEqual(self.loaded,0)
 def test_metadata_digest_mismatch_blocks_even_existing_config_id(self):
  self.present=True;self.registry.values[image.MANIFEST]+=b" "
  with self.assertRaisesRegex(image.ImageFailure,"MANIFEST_DIGEST_DIFFERS"):self.acquire()
  self.assertEqual(self.loaded,0)
 def test_layer_digest_mismatch_blocks_import(self):
  self.registry.values[self.layers[0]["digest"]]=b"x"*self.layers[0]["size"]
  with self.assertRaisesRegex(image.ImageFailure,"LAYER_DIGEST_DIFFERS"):self.acquire()
  self.assertEqual(self.loaded,0)
 def test_engine_change_after_load_is_held_even_if_config_appears(self):
  def observe(args,identity=False):
   if self.loaded and args[:1]==["info"]:return b"replacement\n"
   return self.observe(args,identity)
  with self.assertRaisesRegex(image.ImageFailure,"ENGINE_ID_CHANGED"):self.acquire(observe=observe)
  self.assertEqual(json.loads(self.state.read_text())["phase"],"held")
 def test_import_wrapper_rechecks_socket_before_and_after_mutation_and_holds_post_failure(self):
  def load(archive,end):image.import_archive(archive,end,"engine-one",(1,2))
  with patch.object(image,"engine",return_value=b"engine-one\n"),patch.object(image,"socket_identity",side_effect=[None,image.ImageFailure("IMAGE_ENGINE_SOCKET_CHANGED")]),patch.object(image.subprocess,"run",return_value=subprocess.CompletedProcess([],0,b"",b""))as command:
   with self.assertRaisesRegex(image.ImageFailure,"ENGINE_SOCKET_CHANGED"):self.acquire(load=load)
   self.assertEqual(command.call_count,1);self.assertIn("load",command.call_args.args[0])
  self.assertEqual(json.loads(self.state.read_text())["phase"],"held")
 def test_import_wrapper_refuses_changed_socket_before_mutation(self):
  with patch.object(image,"engine",return_value=b"engine-one\n"),patch.object(image,"socket_identity",side_effect=image.ImageFailure("IMAGE_ENGINE_SOCKET_CHANGED")),patch.object(image.subprocess,"run")as command:
   with self.assertRaisesRegex(image.ImageFailure,"ENGINE_SOCKET_CHANGED"):image.import_archive(self.root/"archive",self.end,"engine-one",(1,2))
   command.assert_not_called()
 def test_inspected_image_wrong_physical_id_cannot_confirm(self):
  def observe(args,identity=False):
   value=self.observe(args,identity)
   return value.replace(image.CONFIG.encode(),b"sha256:"+b"0"*64)if args[:2]==["image","inspect"]else value
  with self.assertRaisesRegex(image.ImageFailure,"IMPORT_IDENTITY_DIFFERS"):self.acquire(observe=observe)
  self.assertEqual(json.loads(self.state.read_text())["phase"],"held")
 def test_json_duplicate_keys_are_not_last_writer_authority(self):
  with self.assertRaisesRegex(image.ImageFailure,"DUPLICATE_KEY"):image.document(b'{"config":1,"config":2}')
 def test_gzip_bomb_trailing_concatenation_and_wrong_diff_id_refuse(self):
  for index,(raw,cap,want,code)in enumerate(((gzip.compress(b"x"*200),100,image.digest(b"x"*200),"UNPACKED_LIMIT"),(gzip.compress(b"x")+b"extra",100,image.digest(b"x"),"TRAILING_DATA"),(gzip.compress(b"x")+gzip.compress(b"y"),100,image.digest(b"xy"),"TRAILING_DATA"),(gzip.compress(b"x")[:-1],100,image.digest(b"x"),"INCOMPLETE"),(gzip.compress(b"x"),100,image.digest(b"y"),"DIFF_ID_DIFFERS"))):
   source=self.root/f"{index}.gzip";source.write_bytes(raw)
   with self.subTest(code=code),self.assertRaisesRegex(image.ImageFailure,code):image.unpack_layer(source,self.root/f"{index}.tar",want,0,self.end,cap)

class EarlyPrerequisiteTests(NativeFixture):
 def test_whole_prerequisite_chain_precedes_first_expensive_command_and_overlay_write(self):
  module=ast.parse((HERE/"native.py").read_text());method=next(x for x in ast.walk(module)if isinstance(x,ast.FunctionDef)and x.name=="execute")
  calls=[(x.lineno,ast.unparse(x.func))for x in ast.walk(method)if isinstance(x,ast.Call)]
  admission=next(line for line,name in calls if name=="accounting.admit");image_=next(line for line,name in calls if name=="accounting.prepare_image");corepack=min(line for line,name in calls if name=="self.run")
  self.assertLess(admission,image_);self.assertLess(image_,corepack)
  for name in("self.source_snapshot","shutil.disk_usage","os.pidfd_open","shutil.which"):
   self.assertTrue(any(line<admission and call==name for line,call in calls),name)
  validation=next(x for x in ast.walk(method)if isinstance(x,ast.For)and "pins['fixtures']"in ast.unparse(x.iter))
  self.assertLess(validation.lineno,admission);self.assertNotIn("write_bytes",ast.unparse(validation))
  self.assertIn("fixture/base differs",ast.unparse(validation))
 def test_import_custody_is_checked_before_no_fixture_record_fast_return(self):
  from native_sandbox import SandboxAccounting,IMAGE,CONFIG
  a=SandboxAccounting(self.n);a.engine_id="engine-one"
  a.image_record.write_text(json.dumps({"format":1,"engineId":"engine-one","image":IMAGE,"runtimeImage":CONFIG,"phase":"held","issued":True}));a.image_record.chmod(0o600)
  self.assertFalse(a.record.exists())
  with self.assertRaisesRegex(RuntimeError,"IMAGE_IMPORT_UNCONFIRMED"):a.assert_retired(self.n.end)
 def test_missing_image_ledger_with_staging_retains_custody(self):
  from native_sandbox import SandboxAccounting
  a=SandboxAccounting(self.n);a.image_staging.mkdir()
  with self.assertRaisesRegex(RuntimeError,"CUSTODY_RECORD_MISSING"):a.assert_retired(self.n.end)
 def test_engine_observation_reresolves_socket_alias_after_cli_returns(self):
  first=self.root/"first.sock";second=self.root/"second.sock"
  with patch.object(Path,"resolve",side_effect=[first,second]),patch.object(Path,"stat",side_effect=[SimpleNamespace(st_dev=1,st_ino=2,st_mode=0o140600),SimpleNamespace(st_dev=1,st_ino=3,st_mode=0o140600)]),patch.object(image.subprocess,"run",return_value=subprocess.CompletedProcess([],0,b"engine-one",b""))as command:
   with self.assertRaisesRegex(image.ImageFailure,"ENGINE_SOCKET_CHANGED"):image.engine(["info"],time.monotonic()+10,"engine-one",(1,2))
   self.assertEqual(command.call_count,1)

if __name__=="__main__":unittest.main()

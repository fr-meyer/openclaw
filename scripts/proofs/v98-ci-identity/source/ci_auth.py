"""Direct GitHub OIDC -> Google STS -> exact service-account token.

Import is inert. Live HTTPS is selected only by the separately gated CI entry.
No SDK, ADC, native-user cache, redirect, alternate issuer or refresh-secret path.
"""
import base64,datetime,json,os,re,ssl,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
from ci_common import Deadline,SelfAlarm,Refusal,need,finite,read_json,publish,directory
REPO='fr-meyer/openclaw';REPO_ID='1309456040';OWNER_ID='26621962'
REF='refs/heads/candidate/v2026.9.8-runtime-qualification'
WORKFLOW='.github/workflows/v98-public-proof-ci.yml'
ENVIRONMENT='v98-public-proof-ci-admission'
PROVIDER='projects/1046324571444/locations/global/workloadIdentityPools/v98-public-proof-ci/providers/github'
AUDIENCE='//iam.googleapis.com/'+PROVIDER
ACCOUNT='v98-public-proof-ci@openclaw-family-gateway.iam.gserviceaccount.com'
SCOPE='https://www.googleapis.com/auth/cloud-platform'
INTENDED_ACCESS_TOKEN_SECONDS=600
STS='https://sts.googleapis.com/v1/token'
MAPPING={'google.subject':'assertion.sub','attribute.repository_id':'assertion.repository_id','attribute.repository_owner_id':'assertion.repository_owner_id','attribute.run_number':'assertion.run_number'}
def provider_condition(b):
 # run_id is provider-assigned only after the approved push. Exact run_number,
 # attempt 1, revision and workflow admit that single first run; the observed
 # run_id is then bound independently by the fresh parent execution review.
 expected={'repository':REPO,'repository_id':REPO_ID,'repository_owner_id':OWNER_ID,'ref':REF,'sha':b['toolingCommit'],'workflow_sha':b['workflowCommit'],'workflow_ref':REPO+'/'+WORKFLOW+'@'+REF,'event_name':'push','run_number':str(b['runNumber']),'run_attempt':'1','runner_environment':'github-hosted','environment':ENVIRONMENT,'sub':b['oidcSubject']}
 return ' && '.join('assertion.'+k+' == '+json.dumps(v)for k,v in expected.items())
def secret(value):return type(value)is str and re.fullmatch('[A-Za-z0-9._~-]{16,16384}',value)is not None
def github_oidc_host(host):
 return(type(host)is str and len(host)<=253 and host.endswith('.actions.githubusercontent.com')
  and all(re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label)is not None for label in host.split('.')))
def binding(value,allow_pending_platform=False):
 expected={'schema':'v98-ci-issuer-binding/v2','repository':REPO,'repositoryId':REPO_ID,'repositoryOwnerId':OWNER_ID,'ref':REF,'workflow':WORKFLOW,'githubEnvironment':ENVIRONMENT,'eventName':'push','provider':PROVIDER,'audience':AUDIENCE,'serviceAccount':ACCOUNT,'scope':SCOPE,'runAttempt':1}
 need(all(type(value.get(k))is type(v)and value[k]==v for k,v in expected.items()),'EXACT_CI_ISSUER_BINDING')
 need(type(value.get('serviceAccountUniqueId'))is str and re.fullmatch('[1-9][0-9]{9,29}',value['serviceAccountUniqueId'])is not None,'IMMUTABLE_SA_ID')
 for key in('toolingCommit','workflowCommit'):need(type(value.get(key))is str and re.fullmatch('[a-f0-9]{40}',value[key])is not None,'EXACT_WORKFLOW_COMMIT')
 need(value['toolingCommit']==value['workflowCommit'],'WORKFLOW_AND_TOOLING_SAME_REVISION')
 need(type(value.get('runNumber'))is int and value['runNumber']>0,'EXACT_CI_FIRST_RUN')
 need((allow_pending_platform and value.get('runId')is None)or(type(value.get('runId'))is int and value['runId']>0),'EXACT_CI_FIRST_RUN')
 subjects=['repo:'+REPO+':environment:'+ENVIRONMENT,'repo:fr-meyer@'+OWNER_ID+'/openclaw@'+REPO_ID+':environment:'+ENVIRONMENT]
 need(value.get('oidcSubject')in subjects and value.get('subjectFormatIndependentlyConfirmed')is True,'EXACT_PRECONFIRMED_SUBJECT_NO_FALLBACK')
 host=value.get('oidcRequestHost');need((allow_pending_platform and host is None)or github_oidc_host(host),'EXACT_GITHUB_OIDC_HOST')
 need(value.get('nativeFallback')is False and value.get('staticKeys')is False,'NO_NATIVE_OR_STATIC_KEYS')
 return value
def claims(jwt,b,now):
 need(type(jwt)is str and len(jwt)<=16384 and jwt.count('.')==2,'BOUNDED_JWT');parts=jwt.split('.')
 try:
  header=read_json(base64.b64decode(parts[0]+'='*(-len(parts[0])%4),altchars=b'-_',validate=True));v=read_json(base64.b64decode(parts[1]+'='*(-len(parts[1])%4),altchars=b'-_',validate=True))
 except BaseException:raise Refusal('MALFORMED_JWT')from None
 need(header.get('alg')=='RS256'and type(header.get('kid'))is str and 0<len(header['kid'])<=256,'EXPECTED_SIGNED_JWT_SHAPE')
 expected={'iss':'https://token.actions.githubusercontent.com','aud':AUDIENCE,'repository':REPO,'repository_id':REPO_ID,'repository_owner_id':OWNER_ID,'ref':REF,'sha':b['toolingCommit'],'workflow_sha':b['workflowCommit'],'workflow_ref':REPO+'/'+WORKFLOW+'@'+REF,'event_name':'push','run_id':str(b['runId']),'run_number':str(b['runNumber']),'run_attempt':'1','runner_environment':'github-hosted','environment':ENVIRONMENT,'sub':b['oidcSubject']}
 need(all(v.get(k)==expected[k]for k in expected),'EXACT_OIDC_CLAIMS')
 need(all(finite(v.get(k))for k in('iat','exp'))and v['iat']<=now<v['exp']<=v['iat']+600,'FRESH_BOUNDED_OIDC')
 # Decoding is only a precheck. Trusted Google STS verifies signature, provider
 # state, attribute mapping and condition before any result is authenticated.
 return True
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None
class TransportFailure(Refusal):
 def __init__(self,status=None):self.status=status if type(status)is int and 100<=status<=599 else None;super().__init__('AUTH_HTTP_ACCESS_DENIED'if self.status in(401,403)else'AUTH_HTTPS_FAILED_NO_RETRY')
class HTTPS:
 def __init__(self,environment):
  need(not any(k in environment for k in('SSL_CERT_FILE','SSL_CERT_DIR','REQUESTS_CA_BUNDLE','CURL_CA_BUNDLE','SSLKEYLOGFILE')),'NO_CUSTOM_TLS_OVERRIDE_OR_SECRET_LOGGING')
  context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_2
  self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),NoRedirect())
 def request(self,method,url,headers,body,deadline,final_check):
  try:
   need(urllib.parse.urlsplit(url).scheme=='https','HTTPS_ONLY');deadline.sample();request=urllib.request.Request(url,data=body,headers=headers,method=method)
   final_check()
   with self.opener.open(request,timeout=max(.001,deadline.remaining()))as response:
    need(response.status==200,'AUTH_HTTP_STATUS');raw=response.read(65537);deadline.sample();need(len(raw)<=65536,'AUTH_BODY_CAP');return read_json(raw)
  except urllib.error.HTTPError as error:
   status=error.code;error.close();raise TransportFailure(status)from None
  except BaseException:raise TransportFailure()from None
class Issuer:
 def __init__(self,b,environment,intent_directory,grant,execution_end,http=None,wall=time.time,mono=time.monotonic,alarm=SelfAlarm):
  self.b=binding(b);self.env=environment;self.root=Path(intent_directory);self.root.mkdir(mode=0o700);directory(self.root)
  self.grant=grant;self.end=execution_end;self.http=http;self.wall=wall;self.mono=mono;self.alarm=alarm;self.count=0;self.halted=False
 def issue(self,required_until):
  try:
   clock=Deadline(min(self.end,self.grant.deadline),self.wall,self.mono,20)
   with self.alarm(clock):return self._issue(required_until,clock)
  except BaseException:self.halted=True;raise Refusal('ISSUER_FAILED_OR_UNKNOWN_NO_RETRY')from None
 def _issue(self,required_until,clock):
  need(not self.halted and self.count<5,'ISSUER_HALTED_OR_BUDGET');self.grant.check();now=self.wall()
  need(finite(required_until)and now<required_until<=now+1200 and required_until<self.end,'BOUNDED_REQUIRED_VALIDITY')
  self.count+=1;index=self.count
  # Durable intent is consumed before reading request secrets or making ANY
  # OIDC/STS/IAM request. A new process cannot adopt this existing directory.
  stage='DURABLE_INTENT'
  try:
   publish(self.root/('issue-'+str(index)+'-intent.json'),{'schema':'v98-ci-issuer-intent/v1','index':index,'entryWall':clock.w,'entryMonotonic':clock.m,'deadline':clock.end,'serviceAccount':ACCOUNT,'provider':PROVIDER,'retryAuthorized':False},clock.sample)
   self.grant.check();clock.sample();rawurl=self.env.get('ACTIONS_ID_TOKEN_REQUEST_URL');bearer=self.env.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN');need(type(rawurl)is str and secret(bearer),'EXACT_GITHUB_REQUEST_INPUT')
   need(len(rawurl)<=8192,'BOUNDED_GITHUB_REQUEST_URL');parsed=urllib.parse.urlsplit(rawurl);need(parsed.scheme=='https'and parsed.hostname==self.b['oidcRequestHost']and parsed.port in(None,443)and parsed.username is None and parsed.password is None and not parsed.fragment,'EXACT_GITHUB_REQUEST_URL')
   query=urllib.parse.parse_qsl(parsed.query,keep_blank_values=True);need(not any(k=='audience'for k,v in query),'NO_PREEXISTING_AUDIENCE');query.append(('audience',AUDIENCE));url=urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
   http=self.http if self.http is not None else HTTPS(self.env)
   def wire():self.grant.check();clock.sample()
   def send(method,url,headers,body):wire();v=http.request(method,url,headers,body,clock,wire);wire();return v
   stage='GITHUB_OIDC';oidc=send('GET',url,{'Authorization':'Bearer '+bearer},None);jwt=oidc.get('value');claims(jwt,self.b,self.wall())
   body=urllib.parse.urlencode({'grant_type':'urn:ietf:params:oauth:grant-type:token-exchange','audience':AUDIENCE,'scope':SCOPE,'requested_token_type':'urn:ietf:params:oauth:token-type:access_token','subject_token_type':'urn:ietf:params:oauth:token-type:jwt','subject_token':jwt}).encode()
   stage='GOOGLE_STS';sts=send('POST',STS,{'Content-Type':'application/x-www-form-urlencoded'},body)
   need(secret(sts.get('access_token'))and sts.get('token_type')=='Bearer'and sts.get('issued_token_type')=='urn:ietf:params:oauth:token-type:access_token'and type(sts.get('expires_in'))is int and 0<sts['expires_in']<=3600,'TRUSTED_STS_ENVELOPE')
   iam_target='https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/'+self.b['serviceAccountUniqueId']+':generateAccessToken'
   stage='GOOGLE_IAM_CREDENTIALS';minted=send('POST',iam_target,{'Authorization':'Bearer '+sts['access_token'],'Content-Type':'application/json'},json.dumps({'scope':[SCOPE],'lifetime':str(INTENDED_ACCESS_TOKEN_SECONDS)+'s'},separators=(',',':')).encode())
   token=minted.get('accessToken');need(secret(token),'MINTED_TOKEN_SHAPE');text=minted.get('expireTime');need(type(text)is str and len(text)<=64,'BOUNDED_EXPIRY');stamp=datetime.datetime.fromisoformat(text.replace('Z','+00:00'));need(stamp.utcoffset()is not None,'AWARE_TOKEN_EXPIRY');expiry=stamp.timestamp();now=self.wall();need(now<required_until<expiry<=now+INTENDED_ACCESS_TOKEN_SECONDS,'MINTED_TOKEN_EXPIRY');self.grant.check();clock.sample()
   public={'schema':'v98-ci-issuer-result/v1','index':index,'status':'COMPLETE_EXACT_STS_AND_IAM_TARGET_RESPONSE','serviceAccount':ACCOUNT,'serviceAccountUniqueId':self.b['serviceAccountUniqueId'],'provider':PROVIDER,'expiresAtEpoch':expiry,'sharedNativeIssuerUsed':False,'tokensOrDerivedHashesRetained':False,'retryAuthorized':False}
   publish(self.root/('issue-'+str(index)+'-result.json'),public,clock.sample);clock.sample()
   return {'schema':'v98-ci-token-envelope/v1','token':token,'acquiredAtEpoch':now,'expiresAtEpoch':expiry,'principal':ACCOUNT,'principalUniqueId':self.b['serviceAccountUniqueId'],'provider':PROVIDER,'identityBasis':'TRUSTED_STS_AND_EXACT_IAM_TARGET_TLS','nativeIssuerUsed':False}
  except BaseException as error:
   self.halted=True
   try:publish(self.root/'issuer-halted.json',{'schema':'v98-ci-issuer-halted/v1','status':'REFUSED_OR_UNKNOWN','stage':stage,'httpStatus':error.status if type(error)is TransportFailure else None,'index':index,'retryAuthorized':False,'secretOrRawErrorRetained':False},clock.sample)
   except BaseException:pass
   raise Refusal('ISSUER_FAILED_OR_UNKNOWN_NO_RETRY')from None

"""Exercise the real public MCP with a caller-supplied capture; never record its bytes."""
import argparse,asyncio,base64,hashlib,json
from datetime import datetime,timedelta,timezone
from pathlib import Path
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

def utc():return datetime.now(timezone.utc).isoformat()
async def main(a):
 raw=Path(a.source).read_bytes(); digest=hashlib.sha256(raw).hexdigest()
 assert len(raw)==10027488 and digest=='85c1ded1fea23cb9277604f7b26a520718eed47445e4624182beb88c2388357f'
 encoded=base64.b64encode(raw).decode('ascii')
 report={'started':utc(),'endpoint':a.endpoint,'source_bytes':len(raw),'source_sha256':digest,'tests':[]}
 out=Path(a.output)
 if out.exists():raise RuntimeError('Refusing to replace previous evidence')
 def save():out.write_text(json.dumps(report,ensure_ascii=False,indent=2))
 async with streamablehttp_client(a.endpoint) as (r,w,_):
  async with ClientSession(r,w,read_timeout_seconds=timedelta(seconds=300)) as s:
   await s.initialize()
   listing=await s.list_tools()
   tool=next(t for t in listing.tools if t.name=='hdfs_upload_file')
   report['upload_tool_schema']=tool.inputSchema;save()
   async def call(label,name,args,error=False):
    started=utc();result=await s.call_tool(name,args)
    data=result.structuredContent
    if data is None:
     texts=[c.text for c in result.content if c.type=='text']
     try:data=json.loads(texts[0])
     except (ValueError,IndexError):data=texts
    if isinstance(data,dict) and set(data)=={'result'}:data=data['result']
    ok=bool(result.isError)==error
    report['tests'].append({'label':label,'tool':name,'started':started,'completed':utc(),'expected_error':error,'isError':bool(result.isError),'pass':ok,'result':data})
    save();print(label,'PASS' if ok else 'FAIL',flush=True)
    if not ok:raise RuntimeError(label)
    return data
   canonical='/student/agentic-siem/additional-evidence/psexec-hunt/psexec-hunt.pcapng'
   target=canonical+'.mcp-upload-verification-20260910'
   args={'destination':target,'content_base64':encoded,'expected_bytes':len(raw),'expected_sha256':digest}
   await call('unique test destination absent','hdfs_stat',{'path':target},error=True)
   x=await call('full capture upload via new MCP tool','hdfs_upload_file',args)
   assert x['destination_verified'] and not x['reused'] and x['staging_removed'] and x['sha256']==digest and x['bytes']==len(raw)
   x=await call('independent uploaded HDFS SHA-256','hdfs_sha256',{'path':target})
   assert x['sha256']==digest
   x=await call('safe replay of full upload','hdfs_upload_file',args)
   assert x['reused'] and x['sha256']==digest
   prefix=raw[:257]
   conflict={**args,'content_base64':base64.b64encode(prefix).decode(),'expected_bytes':len(prefix),'expected_sha256':hashlib.sha256(prefix).hexdigest()}
   await call('different existing content rejected','hdfs_upload_file',conflict,error=True)
   await call('wrong SHA-256 rejected','hdfs_upload_file',{**conflict,'destination':target+'.invalid','expected_sha256':'0'*64},error=True)
   await call('invalid Base64 rejected','hdfs_upload_file',{**conflict,'destination':target+'.invalid','content_base64':'!'*len(conflict['content_base64'])},error=True)
   await call('wrong decoded byte count rejected','hdfs_upload_file',{**conflict,'destination':target+'.invalid','expected_bytes':258},error=True)
   await call('oversize declared upload rejected','hdfs_upload_file',{**conflict,'expected_bytes':33554433},error=True)
   await call('path traversal rejected','hdfs_upload_file',{**conflict,'destination':'/../outside.pcapng'},error=True)
   await call('invalid uploads created no HDFS file','hdfs_stat',{'path':target+'.invalid'},error=True)
   x=await call('conflict left original full bytes intact','hdfs_sha256',{'path':target})
   assert x['sha256']==digest
   x=await call('canonical import retained','hdfs_sha256',{'path':canonical})
   assert x['sha256']==digest
   await call('remove verified duplicate only','hdfs_delete',{'path':target})
   await call('duplicate removed','hdfs_stat',{'path':target},error=True)
   await call('canonical file metadata','hdfs_stat',{'path':canonical})
   inventory=json.loads(Path(a.inventory).read_text())
   # Only the canonical F1-F6 inventory paths supplied with this lab.
   files=inventory['sources'] if isinstance(inventory,dict) else inventory
   for f in files:
    path=f.get('virtual_path') or f.get('path')
    x=await call('NF01 integrity '+Path(path).name,'hdfs_sha256',{'path':path})
    assert x['sha256']==f['sha256'] and x['bytes']==f['bytes']
   await call('HDFS health','hdfs_cluster_status',{})
   await call('Spark health','spark_cluster_status',{})
 report['completed']=utc();report['pass']=True;save()
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--endpoint',required=True);p.add_argument('--output',required=True);p.add_argument('--inventory',required=True)
 asyncio.run(main(p.parse_args()))

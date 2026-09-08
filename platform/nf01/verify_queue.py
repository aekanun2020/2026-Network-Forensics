"""Exercise queue full, replay, and cancellation against the real MCP server."""
import asyncio,json,hashlib,time
from datetime import timedelta,datetime,timezone
from pathlib import Path
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
out=Path('/tmp/nf01-queue-verification.json');audit={'started_at':datetime.now(timezone.utc).isoformat(),'status':'RUNNING','model_calls':0,'calls':[]}
async def run():
 async with streamablehttp_client('http://127.0.0.1:8000/mcp') as (r,w,_):
  async with ClientSession(r,w,read_timeout_seconds=timedelta(seconds=180)) as s:
   await s.initialize()
   async def call(name,args,error=False):
    x=await s.call_tool(name,args);data=x.structuredContent or json.loads(x.content[0].text) if not x.isError else [c.text for c in x.content if hasattr(c,'text')]
    audit['calls'].append({'tool':name,'arguments':args,'is_error':bool(x.isError),'result':data});out.write_text(json.dumps(audit,indent=2)+'\n')
    assert bool(x.isError)==error,(name,data)
    return data
   suffix=str(time.time_ns());fn='queue_control_'+suffix+'.py'
   code='from pyspark.sql import SparkSession\nimport time\ns=SparkSession.builder.appName("NF01-queue-control").getOrCreate()\ntime.sleep(120)\ns.stop()\n'
   await call('spark_save_job',{'filename':fn,'code':code})
   await call('spark_validate_job',{'filename':fn})
   common={'filename':fn,'expected_sha256':hashlib.sha256(code.encode()).hexdigest(),'conf':{'spark.driver.memory':'512m','spark.cores.max':'1'}}
   jobs=[]
   try:
    for i in range(8):
     j=await call('spark_submit_job',{**common,'idempotency_key':suffix+'-'+str(i)});jobs.append(j['job_id'])
    replay=await call('spark_submit_job',{**common,'idempotency_key':suffix+'-0'})
    assert replay['deduplicated'] and replay['job_id']==jobs[0]
    rejected=await call('spark_submit_job',{**common,'idempotency_key':suffix+'-overflow'},error=True)
    assert 'queue is full' in str(rejected)
    st=await call('spark_job_status',{'job_id':jobs[-1]});assert st['status']=='QUEUED'
    cancelled=await call('spark_cancel_job',{'job_id':jobs[-1]});assert cancelled['status']=='CANCELLED'
   finally:
    for job in reversed(jobs):
     await call('spark_cancel_job',{'job_id':job})
   audit['status']='PASS';audit['finished_at']=datetime.now(timezone.utc).isoformat();out.write_text(json.dumps(audit,indent=2)+'\n');print('PASS: real queue limit 8, idempotent replay, queued/running cancellation; test jobs stopped.')
try: asyncio.run(run())
except BaseException as e:
 audit['status']='FAIL';audit['error']=str(e);out.write_text(json.dumps(audit,indent=2)+'\n');raise

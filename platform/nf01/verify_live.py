"""Validate a real MCP/HDFS/Spark installation without invoking any model."""
import asyncio,json,time,hashlib
from datetime import datetime,timezone,timedelta
from pathlib import Path
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
ENDPOINT='http://127.0.0.1:8000/mcp'
ROWS=json.loads(Path('/tmp/evidence-inventory.json').read_text())['sources']
OUT=Path('/tmp/nf01-verification.json')
audit={'started_at':datetime.now(timezone.utc).isoformat(),'endpoint':ENDPOINT,'model_calls':0,'checks':[],'status':'RUNNING'}
def save(): OUT.write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
async def call(s,name,args):
    t=time.monotonic();r=await s.call_tool(name,args)
    data=r.structuredContent or json.loads(r.content[0].text)
    audit['checks'].append({'tool':name,'arguments':args,'is_error':bool(r.isError),'seconds':round(time.monotonic()-t,3),'result':data});save()
    assert not r.isError,(name,data)
    return data
async def reader(n):
    async with streamablehttp_client(ENDPOINT) as (r,w,_):
        async with ClientSession(r,w,read_timeout_seconds=timedelta(seconds=300)) as s:
            await s.initialize();x=await call(s,'hdfs_sha256',{'path':ROWS[2]['path']})
            assert x['sha256']==ROWS[2]['sha256']
            return {'session':n,'verified':True}
async def run():
    async with streamablehttp_client(ENDPOINT) as (r,w,_):
        async with ClientSession(r,w,read_timeout_seconds=timedelta(seconds=300)) as s:
            init=await s.initialize();audit['server']=init.model_dump(mode='json');save()
            tools=await s.list_tools();audit['tools']=[t.name for t in tools.tools]
            for row in ROWS:
                st=await call(s,'hdfs_stat',{'path':row['path']})
                x=await call(s,'hdfs_sha256',{'path':row['path']})
                assert x['bytes']==row['bytes'] and x['sha256']==row['sha256'],row['id']
            for row in ROWS[1:]:
                x=await call(s,'hdfs_read_lines',{'path':row['path'],'start_line':1,'limit':1})
                assert x['lines'][0]['line']==1
            x=await call(s,'hdfs_pcap_packets',{'path':ROWS[0]['path'],'display_filter':'frame.number == 1','limit':1,'payload_bytes':0})
            assert x['matching_packets']==1 and x['source_sha256']==ROWS[0]['sha256']
            for tool in ['spark_cluster_status','hdfs_cluster_status']:
                if tool in audit['tools']: await call(s,tool,{})
            audit['four_concurrent_read_sessions']=await asyncio.gather(*(reader(i) for i in range(1,5)));save()
            jobs=[]
            queue_observed=False
            max_running=0
            for n in range(1,5):
                code='from pyspark.sql import SparkSession\nspark=SparkSession.builder.appName("NF01-capacity-'+str(n)+'").getOrCreate()\nprint("NF01_ROWS="+str(spark.read.text("hdfs://namenode:9000/mcp'+ROWS[2]['path']+'").count()))\nspark.stop()\n'
                fn=f'person{n}_capacity.py'
                await call(s,'spark_save_job',{'filename':fn,'code':code})
                await call(s,'spark_validate_job',{'filename':fn})
                job=await call(s,'spark_submit_job',{'filename':fn,'expected_sha256':hashlib.sha256(code.encode()).hexdigest(),'conf':{'spark.driver.memory':'1g','spark.cores.max':'1','spark.executor.cores':'1','spark.executor.memory':'512m'}})
                jobs.append(job['job_id'])
                queue_observed=queue_observed or job['status']=='QUEUED'
            deadline=time.monotonic()+300
            pending=set(jobs)
            while pending and time.monotonic()<deadline:
                await asyncio.sleep(3)
                snapshot=await call(s,'spark_list_jobs',{'limit':20})
                records=snapshot.get('result',snapshot) if isinstance(snapshot,dict) else snapshot
                active=sum(x['status']=='RUNNING' for x in records if x['job_id'] in jobs)
                max_running=max(max_running,active)
                assert active<=2, 'More than 2 Spark jobs running'
                for job in list(pending):
                    st=await call(s,'spark_job_status',{'job_id':job})
                    if st['status'] in ['SUCCEEDED','FAILED','LAUNCH_FAILED','INTERRUPTED','CANCELLED']:
                        logs=await call(s,'spark_job_logs',{'job_id':job,'tail_lines':100})
                        assert st['status']=='SUCCEEDED',(job,st,logs)
                        assert 'NF01_ROWS=100000' in json.dumps(logs),job
                        pending.remove(job)
            assert not pending,'Spark jobs did not finish within 300s'
            audit['four_spark_jobs']=jobs
            audit['queue_observed']=queue_observed
            audit['max_running_observed']=max_running
            assert queue_observed, 'Queue state not observed'
    audit['status']='PASS';audit['finished_at']=datetime.now(timezone.utc).isoformat();save();print('PASS: real MCP six-file hashes, record/packet reads, four sessions and four Spark jobs; no model calls.')
try: asyncio.run(run())
except BaseException as e:
    audit['status']='FAIL';audit['error']=str(e);save();raise

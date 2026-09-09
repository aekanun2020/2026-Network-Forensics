"""Real external MCP/TLS verification. No model calls or certificate bypass."""
import asyncio
import argparse
import hashlib
import json
import ssl
import socket
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

BASE = Path(__file__).resolve().parent
HOST = '34-142-187-162.sslip.io'
URL = f'https://{HOST}/mcp'
ROWS = json.loads((BASE / 'evidence-inventory.json').read_text())['sources']
OUT = BASE.parents[1] / 'cloud-activities/evidence' / (datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ') + '-public-mcp-verification.json')
AUDIT = {'started_at': datetime.now(timezone.utc).isoformat(), 'endpoint': URL,
         'client_location': 'operator Mac outside GCP VM, direct public HTTPS',
         'sdk_version': '1.30.0', 'model_calls': 0, 'checks': [], 'status': 'RUNNING'}

def save():
    OUT.write_text(json.dumps(AUDIT, ensure_ascii=False, indent=2) + '\n')

async def call(session, name, args):
    start = time.monotonic()
    result = await session.call_tool(name, args)
    data = result.structuredContent
    if data is None:
        data = json.loads(result.content[0].text)
    AUDIT['checks'].append({'tool': name, 'arguments': args, 'is_error': bool(result.isError),
                            'seconds': round(time.monotonic()-start, 3), 'result': data})
    save()
    assert not result.isError, (name, data)
    return data

async def concurrent_reader(number):
    async with streamablehttp_client(URL) as (reader, writer, _):
        async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=300)) as session:
            await session.initialize()
            result = await session.call_tool('hdfs_sha256', {'path': ROWS[1]['path']})
            data = result.structuredContent or json.loads(result.content[0].text)
            assert not result.isError and data['sha256'] == ROWS[1]['sha256']
            return {'session': number, 'f2_sha256': data['sha256'], 'passed': True}

async def main():
    context = ssl.create_default_context()
    with socket.create_connection((HOST, 443), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname=HOST) as connection:
            AUDIT['tls'] = {'version': connection.version(), 'cipher': connection.cipher(),
                            'certificate': connection.getpeercert(),
                            'certificate_sha256': hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest(),
                            'trust_and_hostname_verified': True}
    save()
    async with streamablehttp_client(URL) as (reader, writer, _):
        async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=300)) as session:
            init = await session.initialize()
            AUDIT['server'] = init.model_dump(mode='json')
            listing = await session.list_tools()
            AUDIT['tools'] = [tool.name for tool in listing.tools]
            for row in ROWS:
                data = await call(session, 'hdfs_sha256', {'path': row['path']})
                assert data['sha256'] == row['sha256'] and data['bytes'] == row['bytes'], row['id']
            data = await call(session, 'hdfs_read_lines', {'path': ROWS[1]['path'], 'start_line': 1, 'limit': 1})
            assert data['lines'][0]['line'] == 1
            data = await call(session, 'hdfs_pcap_packets', {'path': ROWS[0]['path'], 'display_filter': 'frame.number == 1', 'limit': 1, 'payload_bytes': 0})
            assert data['matching_packets'] == 1 and data['source_sha256'] == ROWS[0]['sha256']
            AUDIT['four_concurrent_sessions'] = await asyncio.gather(*(concurrent_reader(n) for n in range(1,5)))
            filename = 'public_https_verify_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '.py'
            code = 'from pyspark.sql import SparkSession\nspark=SparkSession.builder.appName("NF01-public-HTTPS-check").getOrCreate()\nprint("NF01_ROWS="+str(spark.read.text("hdfs://namenode:9000/mcp' + ROWS[2]['path'] + '").count()))\nspark.stop()\n'
            await call(session, 'spark_save_job', {'filename': filename, 'code': code})
            await call(session, 'spark_validate_job', {'filename': filename})
            data = await call(session, 'spark_submit_job', {'filename': filename, 'expected_sha256': hashlib.sha256(code.encode()).hexdigest(), 'conf': {'spark.driver.memory': '1g', 'spark.cores.max': '1', 'spark.executor.cores': '1', 'spark.executor.memory': '512m'}})
            job_id = data['job_id']
            AUDIT['spark_job_id'] = job_id
            save()
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                await asyncio.sleep(4)
                status = await call(session, 'spark_job_status', {'job_id': job_id})
                if status['status'] in ['SUCCEEDED', 'FAILED', 'LAUNCH_FAILED', 'INTERRUPTED', 'CANCELLED']:
                    logs = await call(session, 'spark_job_logs', {'job_id': job_id, 'tail_lines': 100})
                    assert status['status'] == 'SUCCEEDED', status
                    assert 'NF01_ROWS=100000' in json.dumps(logs)
                    break
            else:
                raise TimeoutError(f'Spark job {job_id} did not finish within 300 seconds; inspect before cancelling.')
    AUDIT['status'] = 'PASS'
    AUDIT['finished_at'] = datetime.now(timezone.utc).isoformat()
    save()
    print('PASS: trusted public TLS, real MCP, six hashes, record/packet read, four sessions and Spark count=100000. No model calls.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default=HOST, help='Verified target MCP hostname for this VM.')
    parser.add_argument('--output', type=Path, default=OUT, help='New audit JSON file; existing files are never overwritten.')
    args = parser.parse_args()
    HOST = args.host
    URL = f'https://{HOST}/mcp'
    AUDIT['endpoint'] = URL
    OUT = args.output.resolve()
    if OUT.exists():
        parser.error(f'Output already exists: {OUT}')
    OUT.parent.mkdir(parents=True, exist_ok=True)
    try:
        asyncio.run(main())
    except BaseException as error:
        AUDIT['status'] = 'FAIL'
        AUDIT['error'] = str(error)
        save()
        raise

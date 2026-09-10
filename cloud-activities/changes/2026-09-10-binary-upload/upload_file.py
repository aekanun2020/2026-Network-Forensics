"""Upload a local binary via the real hdfs_upload_file MCP tool (requires mcp SDK)."""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import stat
from datetime import timedelta
from pathlib import Path
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MAX_BYTES = 32 * 1024 * 1024

async def upload(args):
    with Path(args.source).open('rb') as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= MAX_BYTES:
            raise ValueError('source must be a regular file of at most 32 MiB')
        content = handle.read(MAX_BYTES + 1)
        after = os.fstat(handle.fileno())
    if len(content) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('source changed while being read; upload cancelled')
    digest = hashlib.sha256(content).hexdigest()
    async with streamablehttp_client(args.endpoint) as (reader, writer, _):
        async with ClientSession(reader, writer, read_timeout_seconds=timedelta(seconds=300)) as session:
            await session.initialize()
            result = await session.call_tool('hdfs_upload_file', {
                'destination': args.destination,
                'content_base64': base64.b64encode(content).decode('ascii'),
                'expected_bytes': len(content),
                'expected_sha256': digest,
            })
            if result.isError:
                raise RuntimeError('; '.join(c.text for c in result.content if c.type == 'text'))
            data = result.structuredContent
            if data is None:
                data = json.loads(next(c.text for c in result.content if c.type == 'text'))
            if not data.get('destination_verified') or data.get('bytes') != len(content) or data.get('sha256') != digest:
                raise RuntimeError('server result did not verify the supplied file')
            print(json.dumps(data, indent=2))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--destination', required=True, help='MCP virtual HDFS path, without /mcp prefix')
    asyncio.run(upload(parser.parse_args()))

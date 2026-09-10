"""Verify the six real ZIPs and rerun deterministic measurements; no MCP/model calls."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

HERE=Path(__file__).resolve().parent
CASE=HERE.parent

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path,help='New directory outside the repository')
    args=parser.parse_args()
    output=args.output.expanduser().resolve()
    if output.is_relative_to(CASE.parents[1]):
        parser.error('Choose an output directory outside this repository')
    if output.exists() or args.output.is_symlink():
        parser.error('Output must not exist; earlier measurements are never overwritten')
    manifest=json.loads((CASE/'evidence/source-manifest.json').read_text())
    verified=[]
    for source in manifest['sources']:
        for field in ['archive','member']:
            if Path(source[field]).name!=source[field]:
                raise ValueError('Unexpected path in source manifest')
        data=(CASE/'evidence'/source['archive']).read_bytes()
        if hashlib.sha256(data).hexdigest()!=source['archive_sha256']:
            raise ValueError('Archive SHA-256 mismatch: '+source['archive'])
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if archive.namelist().count(source['member'])!=1:
                raise ValueError('Missing/duplicate ZIP member')
            member=archive.read(source['member'])
        if len(member)!=source['bytes'] or hashlib.sha256(member).hexdigest()!=source['sha256']:
            raise ValueError('Raw evidence mismatch: '+source['member'])
        verified.append((source,member))
    output.mkdir()  # Exclusive creation; fail rather than overwrite a concurrent run.
    (output/'evidence').mkdir()
    for source,member in verified:
        path=output/'evidence'/source['member']
        path.write_bytes(member)
        path.chmod(0o444)
    shutil.copyfile(HERE/'check_raw.py',output/'check_raw.py')
    with (output/'measurement-summary.json').open('w') as stream:
        subprocess.run([sys.executable,str(output/'check_raw.py')],stdout=stream,check=True)
    tcpdump=shutil.which('tcpdump')
    commands=[[sys.executable,str(output/'check_raw.py')]]
    if tcpdump:
        command=[tcpdump,'-nn','-tt','-q','-r',str(output/'evidence/coherent-course-100k.pcap'),'host 10.70.0.66']
        with (output/'tcpdump-target.txt').open('w') as stream, (output/'tcpdump-stderr.txt').open('w') as error:
            subprocess.run(command,stdout=stream,stderr=error,check=True)
        commands.append(command)
    receipt={'created_at_utc':datetime.now(timezone.utc).isoformat(),
             'method':'Deterministic raw-file measurements only; Codex makes semantic judgments separately',
             'model_calls':0,'mcp_calls':0,'archives_verified':len(verified),
             'source_manifest_sha256':digest(CASE/'evidence/source-manifest.json'),
             'reader_sha256':digest(HERE/'check_raw.py'),'measurements_sha256':digest(output/'measurements.json'),
             'tcpdump_available':bool(tcpdump),'commands':commands}
    if tcpdump:
        receipt['tcpdump_packet_lines']=len((output/'tcpdump-target.txt').read_text().splitlines())
    (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':
    main()

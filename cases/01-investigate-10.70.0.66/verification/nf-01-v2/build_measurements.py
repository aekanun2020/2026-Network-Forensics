"""Fresh NF-01-v2 measurements from six ZIPs; no prior results, MCP or model APIs."""
import argparse
import contextlib
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import runpy
import shutil
import statistics
import subprocess
import zipfile

HERE = Path(__file__).resolve().parent
CASE = HERE.parents[1]
REPO = CASE.parents[1]

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.expanduser().resolve()
    if out.exists() or args.output.is_symlink() or out.is_relative_to(REPO):
        parser.error('Use a new output directory outside the repository')
    manifest_path = CASE / 'evidence/source-manifest.json'
    manifest = json.loads(manifest_path.read_text())
    verified = []
    inventory = []
    for source in manifest['sources']:
        for key in ('archive', 'member'):
            if Path(source[key]).name != source[key]:
                raise ValueError('Unsafe source path')
        archive_path = CASE / 'evidence' / source['archive']
        data = archive_path.read_bytes()
        if sha(data) != source['archive_sha256']:
            raise ValueError('Archive hash mismatch: ' + source['archive'])
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if z.namelist().count(source['member']) != 1:
                raise ValueError('Missing or duplicate member')
            raw = z.read(source['member'])
        if len(raw) != source['bytes'] or sha(raw) != source['sha256']:
            raise ValueError('Raw evidence mismatch: ' + source['member'])
        verified.append((source, raw))
        inventory.append({'id': source['id'], 'filename': source['member'],
                          'archive_path_read': str(archive_path),
                          'raw_path_read': str(out / 'evidence' / source['member']),
                          'hdfs_virtual_identity': source['path'],
                          'bytes_measured': len(raw), 'sha256_measured': sha(raw),
                          'archive_sha256_measured': sha(data), 'matches_manifest': True})
    out.mkdir()
    (out / 'evidence').mkdir()
    for source, raw in verified:
        p = out / 'evidence' / source['member']
        p.write_bytes(raw)
        p.chmod(0o444)
    reader = out / 'check_raw.py'
    shutil.copyfile(HERE.parent / 'check_raw.py', reader)
    # The existing decoder reads raw files only. Its globals expose packet/record locators.
    with (out / 'measurement-summary.json').open('w') as stream, contextlib.redirect_stdout(stream):
        d = runpy.run_path(str(reader))
    selected = {source_id: d[name] for source_id, name in
                [('F2', 'dns'), ('F3', 'conn'), ('F4', 'flow'), ('F5', 'ids'), ('F6', 'fw')]}
    write_json(out / 'selected-records.json', selected)
    write_json(out / 'source-inventory.json', inventory)
    rows = []
    for key, ps in d['target_sessions'].items():
        c = d['bytuple'][key]
        outgoing = [p for p in ps if p['src'] == d['TARGET']]
        incoming = [p for p in ps if p['dst'] == d['TARGET']]
        phase = 'dns' if key[-1] == 'udp' and key[3] == 53 else (
            'http_upload' if any(p['payload'].startswith(b'POST ') for p in outgoing) else 'other_tcp')
        rows.append({'conn_line': c['_line'], 'phase': phase, 'originator': key[0],
                     'originator_port': key[1], 'responder': key[2], 'responder_port': key[3],
                     'protocol': key[4], 'start_epoch': min(p['ts'] for p in ps),
                     'last_epoch': max(p['ts'] for p in ps), 'start_utc': utc(min(p['ts'] for p in ps)),
                     'last_packet_utc': utc(max(p['ts'] for p in ps)),
                     'first_packet': ps[0]['packet'], 'last_packet': ps[-1]['packet'],
                     'out_payload_bytes': sum(p['payload_bytes'] for p in outgoing),
                     'in_payload_bytes': sum(p['payload_bytes'] for p in incoming),
                     'out_ip_bytes': sum(p['ip_bytes'] for p in outgoing),
                     'in_ip_bytes': sum(p['ip_bytes'] for p in incoming),
                     'out_packets': len(outgoing), 'in_packets': len(incoming)})
    rows.sort(key=lambda r: r['conn_line'])
    with (out / 'conversations.tsv').open('w') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]), delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL)
        writer.writeheader(); writer.writerows(rows)
    with (out / 'packets.tsv').open('w') as stream:
        fields = ['packet','utc','src','dst','sport','dport','proto','flags','payload_bytes','ip_bytes','payload_prefix_hex']
        writer = csv.DictWriter(stream, fieldnames=fields, delimiter='\t', lineterminator='\n', quoting=csv.QUOTE_ALL); writer.writeheader()
        for p in d['packets']:
            writer.writerow({**{k:p[k] for k in fields if k!='payload_prefix_hex'},
                             'payload_prefix_hex':p['payload'][:120].hex()})
    phases = {}
    for phase in sorted({r['phase'] for r in rows}):
        group = [r for r in rows if r['phase'] == phase]
        starts = sorted(r['start_epoch'] for r in group)
        intervals = [b-a for a,b in zip(starts,starts[1:])]
        phases[phase] = {'filter': {'dns':'UDP destination port 53',
                                   'http_upload':'TCP originator payload begins POST ',
                                   'other_tcp':'remaining target TCP conversations'}[phase],
                         'conversations':len(group), 'peers':sorted({r['responder'] for r in group}),
                         'first_start_utc':utc(min(starts)), 'last_start_utc':utc(max(starts)),
                         'last_packet_utc':utc(max(r['last_epoch'] for r in group)),
                         'start_span_seconds':max(starts)-min(starts),
                         'packet_span_seconds':max(r['last_epoch'] for r in group)-min(starts),
                         'interval_count':len(intervals),'interval_mean_seconds':statistics.mean(intervals),
                         'interval_stddev_seconds':statistics.pstdev(intervals),
                         'conn_lines':[r['conn_line'] for r in group],
                         'first_packet':min(r['first_packet'] for r in group),
                         'last_packet':max(r['last_packet'] for r in group)}
        for field in ['out_payload_bytes','in_payload_bytes','out_ip_bytes','in_ip_bytes','out_packets','in_packets']:
            phases[phase][field] = sum(r[field] for r in group)
    cardinality = {}
    for name, joins in d['joins'].items():
        left = [j['left_line'] for j in joins]; right = [j['conn_line'] for j in joins]
        deltas = [j.get('delta', 0) for j in joins]
        source = {'dns':'dns','netflow':'flow','firewall':'fw','ids':'ids'}[name]
        cardinality[name] = {'matched_source_records':len(set(left)), 'matched_conn_records':len(set(right)),
                             'source_records':len(d[source]), 'unmatched_source_records':len(d[source])-len(set(left)),
                             'conn_records_without_this_source':len(d['conn'])-len(set(right)),
                             'min_delta_seconds':min(deltas) if name!='firewall' else None,
                             'max_delta_seconds':max(deltas) if name!='firewall' else None}
    metrics = {'measurement_only': True,'phases':phases,'join_cardinality':cardinality,
               'all_originator_netflow_bytes':sum(r['bytes'] for r in d['flow']),
               'all_target_out_payload_bytes':sum(r['out_payload_bytes'] for r in rows),
               'all_target_in_payload_bytes':sum(r['in_payload_bytes'] for r in rows),
               'all_target_out_packets':sum(r['out_packets'] for r in rows),
               'all_target_in_packets':sum(r['in_packets'] for r in rows),
               'dns_queries':sorted({r['query'] for r in d['dns']}),
               'dns_answers':sorted({a for r in d['dns'] for a in r['answers']}),
               'dns_rcodes':sorted({r['rcode_name'] for r in d['dns']}),
               'dns_ttls':sorted({t for r in d['dns'] for t in r['TTLs']}),
               'all_http_bodies_fully_read':True,
               'http_body_sizes':sorted({r['body_bytes'] for r in d['requests']}),
               'http_content_lengths_match':all(r['body_content_length_agrees'] for r in d['requests']),
               'http_single_repeated_byte_bodies':all(len(r['body_unique_byte_values'])==1 for r in d['requests']),
               'http_body_byte_sequence':[r['body_unique_byte_values'] for r in d['requests']]}
    write_json(out / 'metrics.json', metrics)
    tcpdump = shutil.which('tcpdump')
    command = None
    if tcpdump:
        command = [tcpdump,'-nn','-tt','-q','-r',str(out/'evidence/coherent-course-100k.pcap'),'host 10.70.0.66']
        with (out/'tcpdump-target.txt').open('w') as stdout, (out/'tcpdump-stderr.txt').open('w') as stderr:
            subprocess.run(command, stdout=stdout, stderr=stderr, check=True)
    outputs = {p.name:sha(p.read_bytes()) for p in out.iterdir() if p.is_file()}
    receipt = {'question_id':'NF-01-v2','created_at_utc':datetime.now(timezone.utc).isoformat(),
               'source_commit':subprocess.check_output(['git','-C',str(REPO),'rev-parse','HEAD'],text=True).strip(),
               'question_sha256':sha((CASE/'QUESTION.md').read_bytes()),
               'source_manifest_sha256':sha(manifest_path.read_bytes()),
               'builder_sha256':sha(Path(__file__).read_bytes()),
               'method':'Raw ZIP/member verification and deterministic direct-file measurements',
               'prior_results_read':False,'mcp_calls':0,'model_api_calls_by_script':0,
               'tcpdump_command':command,
               'tcpdump_packet_lines':len((out/'tcpdump-target.txt').read_text().splitlines()) if tcpdump else None,
               'output_sha256':outputs}
    write_json(out/'receipt.json',receipt)
    print(json.dumps({'output':str(out),'files_verified':len(inventory),
                      'target_conversations':len(rows),'target_packets':len(d['packets']),
                      'tcpdump_packet_lines':receipt['tcpdump_packet_lines']}))

if __name__ == '__main__':
    main()

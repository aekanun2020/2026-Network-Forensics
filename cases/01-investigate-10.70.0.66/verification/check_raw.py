"""Deterministic measurements of original ZIP members; no MCP or model calls."""
import json, struct, socket, re, statistics, hashlib
from collections import Counter, defaultdict
from pathlib import Path
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parent
E = BASE / 'evidence'
TARGET = '10.70.0.66'
def utc(ts): return datetime.fromtimestamp(ts, timezone.utc).isoformat()
def timeline(values):
    values=sorted(values); ds=[b-a for a,b in zip(values, values[1:])]
    return {'first':utc(values[0]),'last':utc(values[-1]),'interval_count':len(ds),
            'mean_seconds':statistics.mean(ds) if ds else None,
            'population_stddev_seconds':statistics.pstdev(ds) if ds else None}
def load_log(name, field, kv=False):
    selected=[]; total=0; inbound=[]; sim=Counter()
    pattern=re.compile(r'(\w+)=("[^"\\]*(?:\\.[^"\\]*)*"|[^\s]+)')
    with (E/name).open() as f:
        for line,text in enumerate(f,1):
            if kv:
                assert not pattern.sub('',text).strip(), ('unparsed kv',line)
                r={k:json.loads(v) if v.startswith('"') else v for k,v in pattern.findall(text)}
                sim[r.get('simulation')]+=1
            else:r=json.loads(text)
            total+=1
            r['_line']=line
            if r[field]==TARGET:selected.append(r)
            reverse={'id.orig_h':'id.resp_h','source_ip':'destination_ip','srcip':'dstip'}[field]
            if r[reverse]==TARGET:inbound.append(r)
    return selected, {'file':name,'records':total,'target_origin_records':len(selected),
                      'target_destination_records':len(inbound),'simulation_counts':dict(sim)}

dns,ds=load_log('coherent-pcap-zeek-dns-120.jsonl','id.orig_h')
conn,cs=load_log('coherent-pcap-zeek-conn-100k.jsonl','id.orig_h')
flow,ns=load_log('coherent-pcap-netflow-v5-100k.jsonl','source_ip')
ids,ss=load_log('coherent-pcap-suricata-alerts-340.jsonl','source_ip')
fw,fs=load_log('coherent-pcap-fortigate-100k.log','srcip',True)

def cname(c):return (c['id.orig_h'],c['id.orig_p'],c['id.resp_h'],c['id.resp_p'],c['proto'])
def nname(n):return (n['source_ip'],n['source_port'],n['destination_ip'],n['destination_port'],n['network_protocol'])
def fkey(n):return (n['srcip'],int(n['srcport']),n['dstip'],int(n['dstport']),{'6':'tcp','17':'udp'}[n['proto']])
bytuple={cname(c):c for c in conn}; byuid={c['uid']:c for c in conn}
assert len(bytuple)==len(conn)==len(byuid)

# Parse the real classic PCAP bytes; reject unsupported formats rather than substituting data.
raw=(E/'coherent-course-100k.pcap').read_bytes()
assert raw[:4]==b'\xd4\xc3\xb2\xa1'
version_major,version_minor,zone,sigfig,snaplen,linktype=struct.unpack_from('<HHiIII',raw,4)
assert (version_major,version_minor,linktype)==(2,4,1)
pos=24; number=0; packets=[]; target_sessions=defaultdict(list); total_syn=0; total_dns_queries=0
truncated=0; other_ether=0; fragmented=0
while pos<len(raw):
    sec,usec,caplen,wirelen=struct.unpack_from('<IIII',raw,pos);pos+=16
    frame=raw[pos:pos+caplen];pos+=caplen;number+=1
    assert len(frame)==caplen
    truncated+=caplen!=wirelen
    ethertype=struct.unpack_from('!H',frame,12)[0]
    if ethertype!=0x0800:other_ether+=1;continue
    ip=frame[14:]; ihl=(ip[0]&15)*4; length=struct.unpack_from('!H',ip,2)[0]
    assert ip[0]>>4==4 and len(ip)>=length
    frag=struct.unpack_from('!H',ip,6)[0]
    if frag&0x3fff:fragmented+=1;continue
    src=socket.inet_ntoa(ip[12:16]);dst=socket.inet_ntoa(ip[16:20]);proto=ip[9]
    segment=ip[ihl:length]; ts=sec+usec/1e6
    if proto==6:
        sport,dport,seq,ack=struct.unpack_from('!HHII',segment)
        hlen=(segment[12]>>4)*4;flags=segment[13];payload=segment[hlen:]
        total_syn+=bool(flags&2 and not flags&16)
        protocol='tcp'
    elif proto==17:
        sport,dport,udplen,checksum=struct.unpack_from('!HHHH',segment)
        assert udplen==len(segment)
        payload=segment[8:];flags=0;seq=ack=None;protocol='udp'
        if dport==53 and len(payload)>=12 and not (struct.unpack_from('!H',payload,2)[0]&0x8000):total_dns_queries+=1
    else:
        assert TARGET not in (src,dst),('unsupported target IP protocol',proto)
        continue
    if TARGET not in (src,dst):continue
    p={'packet':number,'ts':ts,'utc':utc(ts),'src':src,'dst':dst,'sport':sport,'dport':dport,
       'proto':protocol,'flags':flags,'seq':seq,'ack':ack,'payload':payload,'ip_bytes':length,'payload_bytes':len(payload)}
    packets.append(p)
    key=(src,sport,dst,dport,protocol) if src==TARGET else (dst,dport,src,sport,protocol)
    target_sessions[key].append(p)
assert pos==len(raw)

def dns_name(buf,offset,seen=None):
    seen=set() if seen is None else seen
    assert offset not in seen;seen.add(offset)
    labels=[]
    while True:
        n=buf[offset];offset+=1
        if n==0:return '.'.join(labels),offset
        if n&0xc0==0xc0:
            ptr=((n&0x3f)<<8)|buf[offset]
            tail,_=dns_name(buf,ptr,seen);labels.append(tail)
            return '.'.join(labels),offset+1
        assert n<64
        labels.append(buf[offset:offset+n].decode('ascii'));offset+=n

dns_packets=[]
for p in packets:
    if p['proto']!='udp':continue
    buf=p['payload'];tid,flags,qd,an,ns_,ar=struct.unpack_from('!HHHHHH',buf)
    off=12;questions=[];answers=[]
    for _ in range(qd):
        name,off=dns_name(buf,off);qt,qc=struct.unpack_from('!HH',buf,off);off+=4
        questions.append([name,qt,qc])
    for _ in range(an):
        name,off=dns_name(buf,off);at,ac,ttl,rdlen=struct.unpack_from('!HHIH',buf,off);off+=10
        data=buf[off:off+rdlen];off+=rdlen
        answers.append({'name':name,'type':at,'ttl':ttl,'address':socket.inet_ntoa(data) if at==1 else data.hex()})
    assert ns_==ar==0 and off==len(buf)
    dns_packets.append({'packet':p['packet'],'ts':p['ts'],'response':bool(flags&0x8000),'rcode':flags&15,'tid':tid,'questions':questions,'answers':answers})

packet_disagreements=[]
for key,ps in target_sessions.items():
    c=bytuple.get(key)
    if c is None:packet_disagreements.append({'tuple':key,'error':'no conn record'});continue
    outgoing=[p for p in ps if p['src']==TARGET];incoming=[p for p in ps if p['dst']==TARGET]
    measured={'orig_bytes':sum(p['payload_bytes'] for p in outgoing),'resp_bytes':sum(p['payload_bytes'] for p in incoming),
              'orig_pkts':len(outgoing),'resp_pkts':len(incoming),'orig_ip_bytes':sum(p['ip_bytes'] for p in outgoing),
              'resp_ip_bytes':sum(p['ip_bytes'] for p in incoming)}
    for field,value in measured.items():
        if c[field]!=value:packet_disagreements.append({'line':c['_line'],'field':field,'pcap':value,'log':c[field]})
    if abs(min(p['ts'] for p in ps)-c['ts'])>1e-6:packet_disagreements.append({'line':c['_line'],'field':'ts'})

requests=[];responses=[];lateral=[]
for p in packets:
    if p['proto']!='tcp' or not p['payload']:continue
    if p['src']==TARGET and p['dst']=='203.0.113.66':
        header,body=p['payload'].split(b'\r\n\r\n',1)
        parts=header.decode('ascii').split('\r\n');fields=dict(v.split(': ',1) for v in parts[1:])
        requests.append({'packet':p['packet'],'utc':p['utc'],'request_line':parts[0],'headers':fields,
                         'tcp_payload_bytes':len(p['payload']),'header_bytes':len(header)+4,'body_bytes':len(body),
                         'body_content_length_agrees':len(body)==int(fields['Content-Length']),
                         'body_unique_byte_values':sorted(set(body))})
    elif p['src']=='203.0.113.66':responses.append({'packet':p['packet'],'payload':p['payload'].decode('ascii'),'bytes':len(p['payload'])})
    else:lateral.append({'packet':p['packet'],'utc':p['utc'],'src':p['src'],'dst':p['dst'],'sport':p['sport'],'dport':p['dport'],'payload':p['payload'].decode('ascii')})

joins={'dns':[],'netflow':[],'firewall':[],'ids':[]}; join_errors=[]
for d in dns:
    c=byuid.get(d['uid'])
    if c is None or cname(c)!=cname(d) or c['ts']!=d['ts']:join_errors.append(['dns',d['_line']])
    else:joins['dns'].append({'left_line':d['_line'],'conn_line':c['_line'],'delta':d['ts']-c['ts']})
for n in flow:
    c=bytuple.get(nname(n))
    if c is None or abs(n['ts']-c['ts'])>.01 or n['bytes']!=c['orig_bytes'] or n['packets']!=c['orig_pkts']:join_errors.append(['netflow',n['_line']])
    else:joins['netflow'].append({'left_line':n['_line'],'conn_line':c['_line'],'delta':n['ts']-c['ts']})
for f in fw:
    c=byuid.get(f['parentuid'])
    if c is None or cname(c)!=fkey(f) or int(f['sentbyte'])!=c['orig_bytes'] or int(f['rcvdbyte'])!=c['resp_bytes']:join_errors.append(['firewall',f['_line']])
    else:joins['firewall'].append({'left_line':f['_line'],'conn_line':c['_line'],'printed_time_matches_utc':f['date']+'T'+f['time']==utc(c['ts'])[:19]})
packet_map={p['packet']:p for p in packets}
for s in ids:
    c=bytuple.get(nname(s));p=packet_map.get(s['pcap_count'])
    if c is None or abs(s['ts']-c['ts'])>.01 or p is None or abs(p['ts']-s['ts'])>1e-6 or nname(s)!=(p['src'],p['sport'],p['dst'],p['dport'],p['proto']):join_errors.append(['ids',s['_line']])
    else:joins['ids'].append({'left_line':s['_line'],'conn_line':c['_line'],'packet':s['pcap_count'],'delta':s['ts']-c['ts']})

groups=[]
for port in sorted({c['id.resp_p'] for c in conn}):
    rows=[c for c in conn if c['id.resp_p']==port]
    groups.append({'port':port,'connections':len(rows),'peers':sorted({c['id.resp_h'] for c in rows},key=lambda x:tuple(map(int,x.split('.')))),
                   'record_lines':[c['_line'] for c in rows],'time':timeline([c['ts'] for c in rows]),
                   'orig_bytes':sum(c['orig_bytes'] for c in rows),'resp_bytes':sum(c['resp_bytes'] for c in rows),
                   'states':dict(Counter(c['conn_state'] for c in rows))})
out={'assessor':'Measurements only; semantic assessment is performed by Codex','method':'Direct ZIP member parsing, Python standard library; no MCP, no LLM API, no existing grader',
     'log_counts':[ds,cs,ns,ss,fs], 'pcap':{'total_packets':number,'target_packets':len(packets),'target_conversations':len(target_sessions),
       'target_peers':sorted({p['dst'] if p['src']==TARGET else p['src'] for p in packets}),
       'total_tcp_syn_without_ack':total_syn,'total_dns_queries':total_dns_queries,'truncated_frames':truncated,'other_ether_types':other_ether,'fragmented_packets':fragmented,
       'target_first':packets[0]['utc'],'target_last':packets[-1]['utc'],'packet_log_disagreements':packet_disagreements,
       'target_packet_numbers':[p['packet'] for p in packets], 'tcp_flag_patterns':dict(Counter(str([p['flags'] for p in ps]) for k,ps in target_sessions.items() if k[-1]=='tcp'))},
     'groups':groups,'dns_packets':dns_packets,'http_requests':requests,'http_responses':responses,'lateral_payloads':lateral,
     'joins':joins,'join_errors':join_errors,'ids_signature_counts':dict(Counter(str(s['signature_id']) for s in ids)),
     'ids_alerts_per_conn':dict(Counter(Counter(j['conn_line'] for j in joins['ids']).values()))}
(BASE/'measurements.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({'log_counts':out['log_counts'],'pcap':{k:v for k,v in out['pcap'].items() if k!='target_packet_numbers'},'groups':groups,
      'http':{'requests':len(requests),'tcp_payload_bytes':sum(x['tcp_payload_bytes'] for x in requests),'body_bytes':sum(x['body_bytes'] for x in requests),'header_bytes':sum(x['header_bytes'] for x in requests),'full_bodies_checked':True,'responses':dict(Counter(x['payload'] for x in responses))},
      'lateral_payloads':dict(Counter(x['payload'] for x in lateral)),'join_counts':{k:len(v) for k,v in joins.items()},'join_errors':join_errors,
      'ids_signature_counts':out['ids_signature_counts'],'ids_alerts_per_conn':out['ids_alerts_per_conn']},indent=2))

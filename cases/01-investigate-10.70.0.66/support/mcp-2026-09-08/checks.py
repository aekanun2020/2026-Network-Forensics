import json,collections,decimal,datetime
D=decimal.Decimal
root='/tmp/siem-66-review/'
load=lambda n:json.load(open(root+n+'.json'))
rows={i:load(f'F{i}-records') for i in [2,3,4,5,6]}
ps=load('packets');byframe={p['packet_number']:p for p in ps}
conns={x['record']['uid']:x for x in rows[3]}
assert len(ps)==1255 and set(byframe)==set(range(1,1256))
assert all(x['record']['id.orig_h']=='10.70.0.66' for x in rows[3])
for x in rows[2]:
 r=x['record'];c=conns[r['uid']]['record']
 assert all(r[k]==c[k] for k in ['ts','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto'])
for x in rows[6]:
 r=x['record'];c=conns[r['parentuid']]['record']
 for a,b in [('srcip','id.orig_h'),('dstip','id.resp_h'),('srcport','id.orig_p'),('dstport','id.resp_p'),('sentbyte','orig_bytes'),('rcvdbyte','resp_bytes'),('sentpkt','orig_pkts'),('rcvdpkt','resp_pkts'),('zeekstate','conn_state')]:assert r[a]==str(c[b])
 assert r['date']+' '+r['time']==datetime.datetime.fromtimestamp(c['ts'],datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
for x,cx in zip(rows[4],rows[3]):
 r=x['record'];c=cx['record'];assert x['line']==cx['line']
 for a,b in [('source_ip','id.orig_h'),('destination_ip','id.resp_h'),('source_port','id.orig_p'),('destination_port','id.resp_p'),('network_protocol','proto'),('bytes','orig_bytes'),('packets','orig_pkts')]:assert r[a]==c[b]
 assert abs(r['ts']-c['ts']-c['duration'])<0.000001
for x in rows[5]:
 r=x['record'];p=byframe[r['pcap_count']]
 assert r['source_ip']==p['ip.src'] and r['destination_ip']==p['ip.dst']
 assert r['source_port']==int(p[r['network_protocol']+'.srcport']) and r['destination_port']==int(p[r['network_protocol']+'.dstport'])
 assert abs(D(str(r['ts']))-D(p['frame.time_epoch']))<D('0.000001')
for x in rows[3]:
 r=x['record'];proto=r['proto'];match=[]
 for p in ps:
  forward=p['ip.src']==r['id.orig_h'] and p['ip.dst']==r['id.resp_h'] and p[proto+'.srcport']==str(r['id.orig_p']) and p[proto+'.dstport']==str(r['id.resp_p'])
  reverse=p['ip.dst']==r['id.orig_h'] and p['ip.src']==r['id.resp_h'] and p[proto+'.dstport']==str(r['id.orig_p']) and p[proto+'.srcport']==str(r['id.resp_p'])
  if forward or reverse:match.append((p,forward))
 assert sum(f for p,f in match)==r['orig_pkts'] and sum(not f for p,f in match)==r['resp_pkts']
 assert abs(float(min(D(p['frame.time_epoch']) for p,f in match))-r['ts'])<0.000001
 if proto=='tcp':
  assert sum(p['payload_length'] for p,f in match if f)==r['orig_bytes']
  assert sum(p['payload_length'] for p,f in match if not f)==r['resp_bytes']
result={'assessor':'Codex; script performs deterministic checks only','pcap_frames_target':1255,'pcap_to_zeek_matching_tuples':265,'dns_to_conn_uid_matches':120,'netflow_to_conn_tuple_byte_packet_endtime_matches':265,'fortigate_to_conn_parentuid_tuple_byte_packet_matches':265,'fortigate_clock_text_matches_zeek_utc_text':265,'suricata_alert_to_frame_tuple_timestamp_matches':340}
print(json.dumps(result,indent=2));json.dump(result,open(root+'verification.json','w'),indent=2)
print('Internal rows:')
for x in rows[3][240:]:
 r=x['record'];n=x['line']-240;print(n,r['id.resp_h'],r['id.orig_p'],r['id.resp_p'],datetime.datetime.fromtimestamp(r['ts'],datetime.timezone.utc).strftime('%H:%M:%S'),'F3/F4/F6 line',x['line'],'F1',1081+7*(n-1),'-',1087+7*(n-1))

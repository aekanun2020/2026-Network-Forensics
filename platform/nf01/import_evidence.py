"""Administrator-only import of the six canonical NF-01 files, no other inputs."""
import hashlib,json,subprocess
from pathlib import Path
ROOT=Path('/opt/nf01')
rows=json.loads((ROOT/'evidence-inventory.json').read_text())['sources']
def hdfs(*args):
    return subprocess.run(['docker','compose','-f',str(ROOT/'docker-compose.yml'),'-f',str(ROOT/'compose.lab.yml'),'exec','-T','namenode','hdfs','dfs',*args],check=True,capture_output=True,text=True).stdout
for s in rows:
    p=ROOT/'imports'/s['member'];b=p.read_bytes()
    assert len(b)==s['bytes'] and hashlib.sha256(b).hexdigest()==s['sha256'],s['id']
hdfs('-mkdir','-p','/mcp/student/agentic-siem/incident-lab/input')
for s in rows:
    dest='/mcp'+s['path']
    hdfs('-put','/imports/'+s['member'],dest)
    hdfs('-chown','root:supergroup',dest)
    hdfs('-chmod','444',dest)
hdfs('-chmod','555','/mcp/student/agentic-siem/incident-lab/input')
for n in range(1,5):
    dest=f'/mcp/workspaces/person-{n:02}'
    hdfs('-mkdir','-p',dest)
    hdfs('-chown','spark',dest)
    hdfs('-chmod','700',dest)
print(json.dumps({'imported':[s['path'] for s in rows],'raw_bytes':sum(s['bytes'] for s in rows),'workspace_note':'Named directories share the spark identity; not an authenticated per-user security boundary.'},indent=2))
print(hdfs('-ls','/mcp/student/agentic-siem/incident-lab/input'))

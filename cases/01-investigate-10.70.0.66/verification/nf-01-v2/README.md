# การตรวจ NF-01-v2 จาก local files — ไม่เรียก MCP

[คำตอบอ้างอิงรอบนี้](../../CROSS-CHECK-NF-01-v2.md) · [โจทย์](../../QUESTION.md) · [source manifest](../../evidence/source-manifest.json)

รอบนี้ใช้ shell, Python standard library และ tcpdump อ่านไฟล์ในเครื่องเท่านั้น ไม่เรียก MCP tool ไม่รัน Spark/PySpark และไม่เรียก external model/LLM judge โปรแกรมวัดค่า ส่วน Codex เป็นผู้ประเมินความหมาย ผู้จัดทำเคยเห็นคำตอบเดิมในบทสนทนา จึงไม่ใช่ blind test

## หลักฐานของรอบนี้

- [Source inventory พร้อมชื่อไฟล์/ขนาด/SHA-256](results/SOURCE-INVENTORY.md) และ [paths ที่อ่านจริงแบบ JSON](results/source-inventory.json)
- [Receipt: question hash, code hashes, output hashes และคำสั่ง tcpdump](results/receipt.json)
- [ผลวัดจาก PCAP/logs และ joins](results/measurements.json), [สรุปผลวัด](results/measurement-summary.json) และ [เวลา/ปริมาณ/cardinality](results/metrics.json)
- [Records ของเป้าหมายจากทุก log พร้อม _line](results/selected-records.json) — _line คือเลขบรรทัด raw เดิม ไม่ใช่ลำดับใหม่ใน subset
- [Conversations 265 ชุด](results/conversations.tsv) และ [packets 1,255 รายการ](results/packets.tsv) — เลข packet เป็นเลขจากต้น PCAP; payload_prefix_hex เก็บเพียงส่วนต้นเพื่อเปิดตรวจ ส่วนการนับ body ใช้ payload เต็มจากไฟล์จริง
- [ผล tcpdump](results/tcpdump-target.txt) และ [stderr ของ tcpdump](results/tcpdump-stderr.txt)
- [Snapshot ตัวอ่านที่ใช้จริง](results/check_raw.py) และ [ตัวเตรียม/วัดรอบนี้](build_measurements.py)

ผลอ่านครบ log 300,460 records และ PCAP 699,400 packets พบ 265 conversations/1,255 packets ของเป้าหมาย tcpdump อ่าน PCAP อีกทางได้ 1,255 packet lines ตรงกัน การนับตรงกันเป็นผลตรวจทางเทคนิค ไม่ใช่คำตัดสินเชิงความหมายโดยโปรแกรม

## ทำซ้ำโดยไม่ใช้ MCP

Python 3.9+ และพื้นที่แตกหลักฐานประมาณ 200 MB จาก root repo ให้ใช้ชื่อ output ใหม่ที่ยังไม่มีและอยู่นอก repo:

```sh
python3 cases/01-investigate-10.70.0.66/verification/nf-01-v2/build_measurements.py \
  --output "$HOME/nf01-v2-crosscheck-new"
```

คำสั่งนี้ตรวจ ZIP/member hashes ก่อนสร้าง directory ใหม่ คัดลอก decoder ไปใน directory นั้น แล้วอ่าน raw evidence ใหม่ทั้งหมด ไม่อ่านผลใน prior/, current/, results/ หรือเฉลยเป็น input ใช้ decoder เดิมเป็นโค้ดอ่านไฟล์ มิใช่การนำผลเก่ามาเปลี่ยนชื่อ หากมี tcpdump ใน PATH จะอ่าน PCAP อีกทางและเก็บคำสั่ง/ผลลัพธ์ ถ้าไม่มีจะระบุใน receipt และไม่อ้างว่าตรวจด้วย tcpdump แล้ว

อย่ารัน snapshot check_raw.py ภายใน results/ โดยตรง เพราะ decoder เขียน measurements.json ข้างตัวเอง ให้ใช้ build_measurements.py ซึ่งสร้าง directory ใหม่เสมอ ผล committed ใน results/ เป็น snapshot ที่เก็บรักษาไว้

## ขอบเขตการเชื่อมข้อมูล

ตัวกรองอ่าน target ทั้งสองทิศทางในทุก log และ packet ก่อนคำนวณ ในชุดนี้ target log rows ทุกแถวมี .66 เป็น originator/source; reverse packet traffic ยังคงอยู่ในการนับ PCAP แยกกัน ตัวอ่านจับคู่ F3 ด้วย unique UID/tuple ที่ตรวจว่าไม่ซ้ำในชุดนี้ การใช้ tuple อย่างเดียวอาจไม่พอกับ capture ที่มีการ reuse tuple ซึ่งอยู่นอกขอบเขตการรับรองนี้

phase filters ใน metrics.json คือ UDP destination port 53, TCP ที่ payload ขาออกเริ่ม POST และ TCP ที่เหลือ ตามลำดับ Codex ตรวจปลายทาง/payload/เวลาแล้วจึงอธิบายกลุ่มเหล่านี้ในคำตอบ ไม่มีการกำหนดว่า traffic ต้องเป็น C2 หรือโจมตีสำเร็จไว้ในตัววัด

การผ่าน hashes และเครื่องมืออ่านไฟล์ไม่พิสูจน์ความเป็นอิสระของแหล่งข้อมูล ทั้งหก files มี synthetic parent PCAP ร่วมกันตาม manifest และ cross-check นี้เป็นเฟส direct-file ไม่ใช่การทดสอบ investigator ผ่าน MCP ของโจทย์ v2

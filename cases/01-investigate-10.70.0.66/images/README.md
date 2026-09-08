# ภาพเล่าเหตุการณ์สำหรับผู้เรียน — NF-01

[กลับหน้าหลักโครงการ](../../../README.md) · [สารบัญโจทย์ 01](../README.md) · [โจทย์ NF-01-v2](../QUESTION.md) · [คำตอบ cross-check พร้อม records/packets](../CROSS-CHECK-NF-01-v2.md)

หน้านี้เป็นสื่อประกอบเฉลย ควรเปิดหลังผู้เรียนส่งคำตอบแล้ว ภาพเปิดเผยคู่ติดต่อ เวลา จำนวนครั้ง และปริมาณบางส่วน จึงไม่ใช้เป็น input ในรอบ investigator ที่ต้องค้นจาก raw evidence ตามโจทย์

> **ข้อแก้ไขในการอ่านภาพต้นฉบับ:** ช่อง DNS ต้องอ่านว่า `DNS answer: 203.0.113.66` โดย DNS server คือ `10.70.0.53`; ป้ายหลักฐานของช่อง Outbound ต้องเป็น `[F1, F3, F4, F5]` ภาพยังคงไฟล์ต้นฉบับ รายละเอียดอยู่ใน [Q&A ที่ Codex ประเมินภาพ](../../../Q&A/2026-09-08-nf01-incident-image-review.md)

![ภาพเหตุการณ์ของเครื่อง 10.70.0.66: DNS เป็นคาบ ตามด้วย outbound transfer และ east-west fan-out พร้อมชนิดหลักฐานและเป้าหมาย Agent + MCP](incident-overview-files-wide-th.png)

## หลักฐานสำหรับทำ lab ในโครงการนี้

ZIP ทั้งหกอยู่ใน directory [evidence](../evidence/README.md) ของ `2026-Network-Forensics` ตารางนี้ใช้ชื่อ raw files และรหัส F1–F6 ตาม [QUESTION.md](../QUESTION.md) ทุกไฟล์ ก่อนวิเคราะห์ให้แตก ZIP และตรวจขนาดกับ SHA-256 ของ raw files ตามโจทย์ โดยตรวจตัว archive กับ [source manifest](../evidence/source-manifest.json) แยกกัน

| รหัส | ชนิด / บทบาทในภาพ | ZIP ในโครงการนี้ | ไฟล์ raw ภายใน ZIP |
|---|---|---|---|
| F1 | PCAP ต้นทาง — ครอบคลุมทุกช่วง | [coherent-course-100k.pcap.zip](../evidence/coherent-course-100k.pcap.zip) | `coherent-course-100k.pcap` |
| F2 | DNS — การสอบถามเป็นคาบ | [coherent-pcap-zeek-dns-120.zip](../evidence/coherent-pcap-zeek-dns-120.zip) | `coherent-pcap-zeek-dns-120.jsonl` |
| F3 | Connection — เชื่อม tuple, เวลา และ UID | [coherent-pcap-zeek-conn-100k.zip](../evidence/coherent-pcap-zeek-conn-100k.zip) | `coherent-pcap-zeek-conn-100k.jsonl` |
| F4 | NetFlow — ประกอบการตรวจปริมาณและคู่ติดต่อ | [coherent-pcap-netflow-v5-100k.zip](../evidence/coherent-pcap-netflow-v5-100k.zip) | `coherent-pcap-netflow-v5-100k.jsonl` |
| F5 | IDS — alerts จากกฎที่กำหนด | [coherent-pcap-suricata-alerts-340.zip](../evidence/coherent-pcap-suricata-alerts-340.zip) | `coherent-pcap-suricata-alerts-340.jsonl` |
| F6 | Firewall จำลอง — ผูกกับ F3 ด้วย parentuid | [coherent-pcap-fortigate-100k.zip](../evidence/coherent-pcap-fortigate-100k.zip) | `coherent-pcap-fortigate-100k.log` |

[ผลตรวจไฟล์จาก GitHub วันที่ 8 กันยายน 2026](../evidence/REPOSITORY-CHECK-2026-09-08.json) บันทึก commit ที่ตรวจ Git blob ของแต่ละ archive และค่าที่คำนวณจาก raw member เต็มทั้งไฟล์ เทียบกับ QUESTION.md และ manifest ไม่ใช่การคัดลอก expected hashes มาเป็นผลตรวจ

ZIPs เป็นหลักฐานที่เก็บใน GitHub ส่วน `/student/agentic-siem/incident-lab/input/` เป็น virtual directory บน Spark/HDFS MCP ตามโจทย์ การมี ZIP ใน repo ไม่ยืนยันว่า MCP ของผู้เรียนมี raw files อยู่แล้ว ต้องติดตั้งข้อมูลและตรวจ path/ขนาด/hash ผ่าน MCP จริงก่อนเริ่ม investigator ตามเงื่อนไขใน QUESTION.md ชื่อ ZIP ไม่ใช่ virtual path ที่ใช้แทน raw file ได้

## อ่านภาพร่วมกับข้อสรุปที่ตรวจแล้ว

ใช้เวลา UTC วันที่ 24 สิงหาคม 2026 และแยกพฤติกรรมที่พบออกจากสมมติฐานเรื่องการโจมตี:

| ช่วง | สิ่งที่สังเกตพบ | หลักฐานอ้างอิงใน cross-check |
|---|---|---|
| DNS เป็นคาบ | 120 queries ทุก 60 วินาที เวลาเริ่ม 00:00–01:59; resolver `10.70.0.53` ตอบ A=`203.0.113.66` | F2 #1–120; F1 #1–240 |
| ส่งข้อมูลภายนอก | 120 connections ทุก 10 วินาที เวลาเริ่ม 02:10–02:29:50; TCP payload ขาออก 6,010,330 bytes และขากลับ 240 bytes; HTTP plaintext บน TCP/443 | F3 #121–240; F1 #241–1080 |
| ติดต่อเครื่องภายใน | 25 connections ไป `10.70.1.1` ถึง `10.70.1.25` ทุก 10 วินาที ผ่าน 22/445/3389; เวลาเริ่ม 02:40–02:44 | F3 #241–265; F1 #1081–1255 |

ข้อความ “240 วินาที” ในภาพหมายถึงเวลาเริ่มครั้งแรกถึงเวลาเริ่มครั้งสุดท้าย ช่วงถึง packet สุดท้ายคือ 240.006 วินาที ตรวจรายละเอียด bytes, payload, handshake และข้อจำกัดใน [คำตอบ cross-check](../CROSS-CHECK-NF-01-v2.md)

ชื่อ C2, Data Exfiltration และ Lateral Movement ในภาพเป็นมุมวิเคราะห์ ไม่ยืนยัน compromise การขโมยข้อมูล หรือการควบคุมเครื่อง หลักฐานภายในมี remote-service probe และคำตอบ `OK` แต่ยังไม่ยืนยัน authentication หรือการรันคำสั่ง

## การเชื่อม records และขอบเขตหลักฐาน

- DNS ในภาพใช้ F1 + F2 + F5; outbound ใช้ F1 + F3 + F4 + F5; fan-out ใช้ F1 + F3 + F5
- F6 เป็น firewall view จำลอง ผูกกับ F3 ด้วย `parentuid` ไม่ใช่ผลสังเกตจาก firewall appliance จริง
- รายการข้างต้นเป็นคำอธิบายส่วนต่าง ๆ ของภาพ ไม่ใช่ตัวกรองขอบเขต investigator: ต้องตรวจ `10.70.0.66` ทั้งต้นทางและปลายทางให้ครบทั้งหกไฟล์ตามโจทย์ ไฟล์เดียวอาจครอบคลุมหลายช่วงพฤติกรรม
- ทั้งชุดมี synthetic parent PCAP ร่วมกัน ไม่ถือว่าหกชื่อไฟล์เป็นพยานอิสระหกแหล่ง
- ภาพเป็นภาพประกอบการเรียนที่สร้างด้วย imagegen ไม่ใช่ screenshot หรือผลรันใหม่ แถบ Agent + MCP → Correlation + Timeline → รายงาน เป็นเป้าหมาย lab ไม่ใช่หลักฐานว่ารันครบสายสำเร็จแล้ว

## เปิดผลตรวจที่เก็บในโครงการนี้

รายการต่อไปนี้เป็นผลตรวจ NF-01-v2 ที่บันทึกไว้ใน repo นี้ ไม่ใช่ไฟล์ raw input และไม่ใช่การเปลี่ยนชื่อผลจากภาพต้นทางให้เป็นผลรันใหม่:

- [วิธีตรวจและขอบเขตการตรวจจาก local files](../verification/nf-01-v2/README.md)
- [Source inventory พร้อมขนาดและ hashes](../verification/nf-01-v2/results/SOURCE-INVENTORY.md)
- [ผลวัดจาก PCAP/logs และการจับคู่](../verification/nf-01-v2/results/measurements.json)
- [เวลา ปริมาณ และ cardinality](../verification/nf-01-v2/results/metrics.json)
- [Records ของเป้าหมายพร้อมเลขบรรทัด raw](../verification/nf-01-v2/results/selected-records.json)
- [Conversations](../verification/nf-01-v2/results/conversations.tsv) และ [packets](../verification/nf-01-v2/results/packets.tsv)
- [ทะเบียนที่มาของภาพและการปรับเอกสาร](PROVENANCE.md)

ผลตรวจและภาพนี้ใช้ในเฟสทบทวนเฉลย ต้องไม่ส่งให้ investigator แทน raw files หรือใช้เป็น input เพื่อหาคำตอบตามโจทย์ NF-01-v2

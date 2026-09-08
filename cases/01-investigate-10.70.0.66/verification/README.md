# ผลตรวจคำตอบและการทำซ้ำจากไฟล์โดยไม่ใช้ MCP

[โจทย์เดิม](../QUESTION-v1.md) · [คำตอบเดิม](../AGENT-ANSWER.md) · [เฉลย](../REFERENCE-ANSWER.md) · [หลักฐาน](../evidence/README.md)

ผลที่บันทึกด้านล่างเกิดก่อน [NF-01-v2](../QUESTION.md) ไม่ใช่ผลรัน investigator หรือผลเปรียบเทียบ agent ด้วยโจทย์ฉบับใหม่

ผู้ประเมินความหมายคือ **Codex ในรอบจัดวางนี้ วันที่ 8 กันยายน 2026** ตรวจคำตอบเดิมและผลอ่าน raw files ซ้ำด้วย [check_raw.py](check_raw.py) และ tcpdump ไม่เรียก MCP และไม่ใช้ external model/LLM judge สคริปต์วัดค่าเชิงกำหนดแน่นอน ไม่ได้สร้างข้อวินิจฉัยแทน Codex

## แยกต้นฉบับ ผลเดิม และผลตรวจซ้ำ

- [คำตอบต้นฉบับที่ผู้ใช้ส่งมา](../support/agent-answer-original.txt) คัดลอกตรงทุก byte; [ฉบับอ่านบน GitHub](../AGENT-ANSWER.md) เปลี่ยนเฉพาะลิงก์และเพิ่มคำอธิบายที่มานอกเนื้อหาเดิม
- [ผลวัดก่อนจัดวาง](prior/measurements.json), [integrity ก่อนจัดวาง](prior/integrity.json), [tcpdump ก่อนจัดวาง](prior/tcpdump-target.txt) และ [ยอด tcpdump เดิม](prior/tcpdump-counts.json) คัดลอกโดยไม่แก้และไม่เปลี่ยนให้เป็นผลใหม่
- [ผลวัดซ้ำรอบจัดวาง](current/measurements.json), [สรุปการวัด](current/measurement-summary.json), [receipt ของรอบนี้](current/receipt.json), [tcpdump รอบนี้](current/tcpdump-target.txt) และ [stderr ของ tcpdump](current/tcpdump-stderr.txt) เกิดจากอ่าน ZIPs ที่วางใน repo นี้จริง

รอบนี้ตรวจ archive/member hashes ผ่านทั้งหกไฟล์ ผล measurements.json เท่ากับผลก่อนหน้า และ tcpdump output ตรงกันทุก byte โดยมี 1,255 packet lines การเท่ากันเป็นผลเปรียบเทียบข้อมูล ไม่ใช่การตัดสินความถูกต้องเชิงความหมายแบบอัตโนมัติ

## ข้อวินิจฉัยของ Codex

| ประเด็นในคำตอบเดิม | ผลประเมิน | เหตุผลจากหลักฐาน |
|---|---|---|
| 27 IP, 265 การติดต่อ, 1,255 packets | ตรง | PCAP และ C ตรงกัน; เพิ่มว่า 265 รวม DNS exchanges 120 กับ TCP conversations 145 |
| DNS 120 ครั้งทุก 60 วินาที | ตรง | D/C #1–120; P #1–240; 119 intervals เท่ากับ 60 วินาที |
| ลำดับ DNS → ส่งออก → ภายใน | ตรง แต่ควรชัดเรื่องเวลา | เวลาหลักเป็น first/last conversation start; packet สุดท้ายของ outbound/internal ช้ากว่า start สุดท้าย 6 ms |
| HTTP ข้อความล้วนบน TCP/443 | ตรง | P #244–1077 ทุก 7 packets แสดง POST/headers; ป้าย HTTPS ใน F ไม่ตรงกับ payload |
| 6,010,330 bytes = body 6,000,000 + headers 10,330 | ตรง | ตรวจครบ 120 payloads และเทียบ C/N/F #121–240 |
| รับกลับ OK รวม 240 bytes | ตรง | P #245–1078 ทุก 7 packets มี 2 bytes ต่อครั้ง ไม่พิสูจน์การบันทึกหรือประมวลผลสำเร็จ |
| Body อ่านเฉพาะส่วนต้น | เป็นข้อจำกัดของคำตอบเดิม; ตรวจเพิ่มแล้ว | รอบ direct-file อ่านเต็มทุก body พบอักขระเดียวซ้ำ 50,000 bytes วน A–T ไม่แก้คำตอบเดิมให้ดูเหมือนอ่านเต็มมาแล้ว |
| ภายใน 25 เครื่อง พอร์ต 22/445/3389 = 9/8/8 | ตรง | C #241–265 และ P #1081–1255; probe 35 bytes / OK 2 bytes ทุกคู่ |
| D–C 120, C–N/F 265 และ S 340 → C 265 | ตรงตาม joins ที่ตรวจ | ไม่มี join_errors ในผลวัด; internal 100 alerts = 4 ต่อ 25 conversations |
| Reverse NetFlow rows ไม่มี แต่มี response | ตรง | N target_destination_records=0 ขณะที่ P และ C/F มี payload ขากลับ |
| ยังยืนยัน C2, ขโมยไฟล์, remote execution ไม่ได้ | จำกัดข้อสรุปเหมาะสม | หลักฐานแสดงการรับส่งข้อมูลและ probe; ไม่มี artifact ที่ยืนยันการกระทำเหล่านั้น |
| ที่มาของหลักฐานทั้งชุด | ควรเพิ่มเติม | source_relationship ใน manifest ระบุ synthetic parent PCAP ร่วมกัน ไม่ใช่เฉพาะ F ที่เป็น simulation |

คำตอบอ้างอิงเพิ่มคำอธิบายสามส่วนหลัก: provenance ร่วมกัน, การอ่าน body เต็ม และนิยามเวลาสิ้นสุด ไม่พบตัวเลขหรือ locators สำคัญในคำตอบเดิมที่ขัดกับการตรวจข้างต้น ไม่ให้คะแนนความแม่นยำทั่วไปจากโจทย์เดียว

## ทำซ้ำ

ต้องมี Python 3.9+ และพื้นที่สำหรับแตกหลักฐานประมาณ 200 MB โปรแกรมอ่านนี้ใช้ Python standard library; ถ้ามี tcpdump ใน PATH จะตรวจอีกทางด้วย ไม่มี Python agent หรือ model API call

จาก root repo ตั้งชื่อ output ที่ยังไม่มีอยู่และอยู่นอก repo:

```sh
python3 cases/01-investigate-10.70.0.66/verification/recheck.py \
  --output "$HOME/network-forensics-case01-recheck"
```

โปรแกรมตรวจ ZIP/member SHA-256 ก่อนสร้าง output และไม่เขียนทับ directory เดิม ผลใหม่มี evidence/, check_raw.py, measurements.json, measurement-summary.json และ receipt.json ถ้ามี tcpdump จะมี output/stderr เพิ่ม ถ้าไม่มี tcpdump ให้ถือว่ายังไม่ได้ cross-check ด้วยเครื่องมือนั้น

ตัวอ่าน [check_raw.py](check_raw.py) รักษา bytes ของสคริปต์ตรวจเดิมไว้ รองรับ classic little-endian PCAP/Ethernet/IPv4 ตามไฟล์จริงของโจทย์นี้ ไม่ใช่ decoder ทั่วไปหรือ TCP reassembly engine สำหรับ capture ทุกแบบ ในชุดนี้ไม่พบ truncated frame, IP fragmentation หรือ EtherType อื่น และ HTTP request แต่ละชุดอยู่ใน packet payload เดียว ห้ามนำผลผ่านของชุดนี้ไปอ้างว่าตัวอ่านรองรับ capture รูปแบบอื่นแล้ว

## ขอบเขตของการเผยแพร่

นี่คือการจัดวางโจทย์ คำตอบเดิม และเฉลยที่ตรวจแล้ว พร้อมการวัดซ้ำจากไฟล์ ไม่ใช่การรัน investigator ด้วย Codex prompts ใหม่ใน PR ของ repo ต้นทาง ไม่แก้ผลเดิม ไม่ใช้เครื่องมือวัดเป็น semantic judge และไม่เปลี่ยนบริการหรือ containers ใด

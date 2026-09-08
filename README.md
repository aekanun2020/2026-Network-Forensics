# Network Forensics — โจทย์ คำตอบ และเฉลยจากหลักฐาน

ชุดเรียนนี้แยก **คำตอบที่ agent ให้มา** ออกจาก **เฉลยที่ Codex ตรวจจาก raw evidence** ผู้เรียนควรทำโจทย์และตรึงคำตอบของตนก่อนเปิดเฉลย

| โจทย์ | คำถาม | คำตอบของ agent | เฉลยที่ตรวจแล้ว |
|---|---|---|---|
| 01 — กิจกรรมของ 10.70.0.66 | [โจทย์และขอบเขต](cases/01-investigate-10.70.0.66/QUESTION.md) | [คำตอบ Codex ที่ผู้ใช้ส่งมาตรวจ](cases/01-investigate-10.70.0.66/AGENT-ANSWER.md) | [คำตอบอ้างอิงพร้อม records/packets](cases/01-investigate-10.70.0.66/REFERENCE-ANSWER.md) |

## เปิดหลักฐานและตรวจคำตอบ

- [สารบัญโจทย์ 01](cases/01-investigate-10.70.0.66/README.md)
- [หลักฐาน ZIP หกไฟล์และ hashes](cases/01-investigate-10.70.0.66/evidence/README.md)
- [ผลประเมินของ Codex และวิธี cross-check โดยไม่ใช้ MCP](cases/01-investigate-10.70.0.66/verification/README.md)
- [ตัววัดจากไฟล์จริง](cases/01-investigate-10.70.0.66/verification/check_raw.py) และ [คำสั่งตรวจซ้ำ](cases/01-investigate-10.70.0.66/verification/recheck.py)
- [คำตอบต้นฉบับตรงทุก byte](cases/01-investigate-10.70.0.66/support/agent-answer-original.txt) และ [ทะเบียนที่มา/ไฟล์ที่คัดลอก](cases/01-investigate-10.70.0.66/PROVENANCE.json)

ข้อมูลโจทย์ 01 เป็นชุดสังเคราะห์ที่มี PCAP ต้นทางร่วมกัน ไม่ใช่เหตุโจมตีจริงที่ได้รับการยืนยัน คำตอบของ agent และผลวัดก่อนหน้านี้ถูกเก็บตามที่มา ไม่เปลี่ยนให้เป็นผลรัน Codex รอบใหม่ และไม่มี Python agent หรือ external LLM judge ในขั้นตอนตรวจคำตอบ

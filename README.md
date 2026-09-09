# Network Forensics — โจทย์ คำตอบ และเฉลยจากหลักฐาน

ชุดเรียนนี้แยก **คำตอบที่ agent ให้มา** ออกจาก **เฉลยที่ Codex ตรวจจาก raw evidence** ผู้เรียนควรทำโจทย์และตรึงคำตอบของตนก่อนเปิดเฉลย

## หนังสือประกอบการเรียน

- [จาก Network Traffic สู่หลักฐานการสืบสวน](book/network-forensics-and-log-analysis-th.md) — หนังสือภาษาไทยทั้งฉบับ พร้อมแผนภาพ Mermaid ครอบคลุม PCAP, Flow, Security Logs, Correlation และ SIEM

คัดลอกทั้งไฟล์จาก [2026-Digital-Forensic ณ commit `6513b294d7da434e18123711e4410cbcc54017de`](https://github.com/aekanun2020/2026-Digital-Forensic/blob/6513b294d7da434e18123711e4410cbcc54017de/book/network-forensics-and-log-analysis-th.md) โดยคงเนื้อหา แผนภาพ และบรรณานุกรมตามต้นฉบับ ตัวอย่างในหนังสือเป็นสถานการณ์สมมติแยกจากหลักฐานและเฉลยของโจทย์ 01

## โจทย์และคำตอบ

| โจทย์ | คำถาม | คำตอบของ agent | เฉลยที่ตรวจแล้ว |
|---|---|---|---|
| 01 — กิจกรรมของ 10.70.0.66 | [NF-01-v2: ชื่อไฟล์และ paths เต็มในคำถาม พร้อม hashes](cases/01-investigate-10.70.0.66/QUESTION.md) | [คำตอบ Codex ผ่าน MCP — 8 ก.ย. 2026](cases/01-investigate-10.70.0.66/AGENT-ANSWER-MCP-2026-09-08.md) · [คำตอบเดิม](cases/01-investigate-10.70.0.66/AGENT-ANSWER.md) | [คำตอบ cross-check ตาม NF-01-v2 — ไม่เรียก MCP](cases/01-investigate-10.70.0.66/CROSS-CHECK-NF-01-v2.md) |
| 02 — หลายเหตุการณ์ หรือการโจมตีเดียวกัน? | [NF-02: เชื่อมโยงเหตุการณ์จาก log เพิ่มเติม](cases/02-test-c2-exfil-lateral/QUESTION.md) · [ไฟล์หลักฐาน 11 ชุด](cases/02-test-c2-exfil-lateral/EVIDENCE.md) | — | — |

ส่งโจทย์ NF-01-v2 ทั้งหน้าให้ agent เพื่อให้ได้รับขอบเขตเดียวกัน อ่าน [เหตุผลและหลักฐานรองรับการแก้โจทย์](cases/01-investigate-10.70.0.66/QUESTION-CHANGELOG.md) และ [โจทย์เดิม](cases/01-investigate-10.70.0.66/QUESTION-v1.md) คำตอบเดิมยังเป็นผลต่อโจทย์เดิม ส่วนคำตอบผ่าน MCP วันที่ 8 กันยายน 2026 ใช้ [ข้อความโจทย์ที่ได้รับจริง](cases/01-investigate-10.70.0.66/support/mcp-2026-09-08/question-original.txt) ซึ่งมีคำถามและ paths หกไฟล์ แต่ไม่ได้รับ NF-01-v2 ครบทั้งหน้า จึงไม่จัดเป็นผลเปรียบเทียบ agent ด้วย input มาตรฐานเดียวกัน

[คำตอบ cross-check รอบใหม่](cases/01-investigate-10.70.0.66/CROSS-CHECK-NF-01-v2.md) ใช้ผลอ่าน local files ใหม่โดยไม่เรียก MCP พร้อมตาราง claims/locators และ [หลักฐานวิธีตรวจซ้ำ](cases/01-investigate-10.70.0.66/verification/nf-01-v2/README.md) เป็นคำตอบอ้างอิงของเฟสตรวจ ไม่ใช่ผล investigator ผ่าน MCP; [คำตอบอ้างอิงเดิม](cases/01-investigate-10.70.0.66/REFERENCE-ANSWER.md) ยังคงอยู่แยกกัน

## เปิดหลักฐานและตรวจคำตอบ

- [ผลตรวจ ZIP และ raw files ทั้งหกจาก GitHub เทียบกับโจทย์](cases/01-investigate-10.70.0.66/evidence/REPOSITORY-CHECK-2026-09-08.json) — ดาวน์โหลดและตรวจ hashes วันที่ 8 กันยายน 2026
- [ทะเบียนที่มาของภาพประกอบ NF-01](cases/01-investigate-10.70.0.66/images/PROVENANCE.md) — ตัวระบุต้นทางและ hashes พร้อมประวัติการปรับเอกสาร
- [ภาพเล่าเหตุการณ์ NF-01 พร้อมคำอธิบายและรายการ F1–F6](cases/01-investigate-10.70.0.66/images/README.md) — เปิดหลังส่งคำตอบ; ภาพพร้อมคำแก้ไขในการอ่านและลิงก์เอกสาร/ZIP ภายในโครงการ
- [Q&A ฉบับปรับลิงก์: ภาพเล่าเหตุการณ์สอดคล้องกับโจทย์ NF-01 อย่างไร](Q&A/2026-09-08-nf01-incident-image-review.md) — ผลประเมินของ Codex ก่อนปรับ README ภาพ ใช้ลิงก์ภายในโครงการ
- [ต้นฉบับ Q&A ก่อนปรับลิงก์](Q&A/originals/2026-09-08-nf01-incident-image-review.original.txt) และ [ทะเบียนที่มาพร้อม SHA-256](Q&A/2026-09-08-nf01-incident-image-review.provenance.json) — เก็บข้อความเดิมทุก byte
- [หลักฐานรอบคำตอบ MCP วันที่ 8 กันยายน 2026](cases/01-investigate-10.70.0.66/support/mcp-2026-09-08/README.md) — source inventory, queries/outputs, packets และข้อผิดพลาดที่เก็บไว้
- [ต้นฉบับคำตอบ MCP รอบนี้](cases/01-investigate-10.70.0.66/support/agent-answer-mcp-2026-09-08-original.txt) และ [ทะเบียนที่มาของรอบนี้](cases/01-investigate-10.70.0.66/support/mcp-2026-09-08/provenance.json)
- [สารบัญโจทย์ 01](cases/01-investigate-10.70.0.66/README.md)
- [หลักฐาน ZIP หกไฟล์และ hashes](cases/01-investigate-10.70.0.66/evidence/README.md)
- [ผลประเมินของ Codex และวิธี cross-check โดยไม่ใช้ MCP](cases/01-investigate-10.70.0.66/verification/README.md)
- [ตัววัดจากไฟล์จริง](cases/01-investigate-10.70.0.66/verification/check_raw.py) และ [คำสั่งตรวจซ้ำ](cases/01-investigate-10.70.0.66/verification/recheck.py)
- [คำตอบต้นฉบับตรงทุก byte](cases/01-investigate-10.70.0.66/support/agent-answer-original.txt) และ [ทะเบียนที่มา/ไฟล์ที่คัดลอก](cases/01-investigate-10.70.0.66/PROVENANCE.json)

ข้อมูลโจทย์ 01 เป็นชุดสังเคราะห์ที่มี PCAP ต้นทางร่วมกัน ไม่ใช่เหตุโจมตีจริงที่ได้รับการยืนยัน คำตอบของ agent และผลวัดก่อนหน้านี้ถูกเก็บตามที่มา ไม่เปลี่ยนให้เป็นผลรัน Codex รอบใหม่ และไม่มี Python agent หรือ external LLM judge ในขั้นตอนตรวจคำตอบ

## การติดตั้งและกิจกรรม Cloud

- [บันทึกกิจกรรม GCP](cloud-activities/README.md)
- [ชุดติดตั้ง container สำหรับ NF-01 — HTTPS MCP ผ่านการทดสอบจากภายนอกแล้ว](platform/nf01/README.md)

- [วิธีเชื่อม Claude Desktop กับ NF-01 MCP](platform/nf01/CLAUDE-DESKTOP.md)

- [ผลตรวจกลับมาใช้งานหลัง Start VM วันที่ 9 กันยายน](cloud-activities/2026-09-09-001-student-1-restore.md)

- [บันทึกการตั้งค่า VM กลุ่ม 2–4](cloud-activities/2026-09-09-002-configure-cloned-labs.md)

- [ตาราง MCP URL และคู่มือ Claude Desktop สำหรับทั้ง 4 กลุ่ม](platform/nf01/GROUP-ENDPOINTS.md)

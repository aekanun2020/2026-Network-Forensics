# Network Forensics — แบบฝึกสืบสวนจากหลักฐานเครือข่าย

ฝึกตรวจสอบกิจกรรมของ `10.70.0.66` จากหลักฐาน F1–F6 แล้วอธิบายข้อค้นพบพร้อมอ้างอิงข้อมูลต้นทาง ชุดข้อมูลนี้เป็นข้อมูลสังเคราะห์ที่มี PCAP ต้นทางร่วมกัน

## เริ่มทำแบบฝึก

1. อ่าน [โจทย์ NF-01-v2](cases/01-investigate-10.70.0.66/QUESTION.md) ให้ครบทั้งหน้า
2. เปิด [หลักฐานหกไฟล์ พร้อมขนาดและ SHA-256](cases/01-investigate-10.70.0.66/evidence/README.md)
3. วิเคราะห์และส่งคำตอบก่อนเปิดคำตอบตัวอย่างและเฉลย

## ตรวจคำตอบหลังทำแบบฝึก

- [คำตอบ Codex ผ่าน MCP — 8 กันยายน 2026](cases/01-investigate-10.70.0.66/AGENT-ANSWER-MCP-2026-09-08.md)
- [เฉลย cross-check ของ NF-01-v2 พร้อมหลักฐานอ้างอิง](cases/01-investigate-10.70.0.66/CROSS-CHECK-NF-01-v2.md)
- [ภาพเล่าเหตุการณ์ พร้อมคำอธิบายและรายการ F1–F6](cases/01-investigate-10.70.0.66/images/README.md)

คำตอบผ่าน MCP เป็นบันทึกรอบที่ไม่ได้รับ NF-01-v2 ครบทั้งหน้า ส่วนเฉลย cross-check ตรวจจากไฟล์หลักฐานโดยไม่เรียก MCP จึงใช้ทั้งสองเอกสารเพื่อศึกษาวิธีตรวจคำตอบ ไม่ใช้เป็นผลเปรียบเทียบ agent ภายใต้โจทย์เดียวกัน

## อ่านประกอบ

- [จาก Network Traffic สู่หลักฐานการสืบสวน](book/network-forensics-and-log-analysis-th.md) — PCAP, Flow, Security Logs, Correlation และ SIEM; ตัวอย่างในหนังสือแยกจากชุดหลักฐาน NF-01
- [สารบัญเอกสารโจทย์ 01](cases/01-investigate-10.70.0.66/README.md)

<details>
<summary>บันทึกการจัดทำและตรวจสอบย้อนหลัง สำหรับผู้ดูแลเอกสาร</summary>

รายการต่อไปนี้เป็นประวัติการจัดทำ ผลตรวจย้อนหลัง และงานดูแลระบบ ไม่ใช่ขั้นตอนที่ผู้เรียนต้องทำในแบบฝึก

- [ผลตรวจ ZIP และ raw files ทั้งหกจาก GitHub เทียบกับโจทย์](cases/01-investigate-10.70.0.66/evidence/REPOSITORY-CHECK-2026-09-08.json) — ดาวน์โหลดและตรวจ hashes วันที่ 8 กันยายน 2026
- [ทะเบียนที่มาของภาพประกอบ NF-01](cases/01-investigate-10.70.0.66/images/PROVENANCE.md) — ตัวระบุต้นทางและ hashes พร้อมประวัติการปรับเอกสาร
- [Q&A ฉบับปรับลิงก์: ภาพเล่าเหตุการณ์สอดคล้องกับโจทย์ NF-01 อย่างไร](Q&A/2026-09-08-nf01-incident-image-review.md) — ผลประเมินของ Codex ก่อนปรับ README ภาพ ใช้ลิงก์ภายในโครงการ
- [ต้นฉบับ Q&A ก่อนปรับลิงก์](Q&A/originals/2026-09-08-nf01-incident-image-review.original.txt) และ [ทะเบียนที่มาพร้อม SHA-256](Q&A/2026-09-08-nf01-incident-image-review.provenance.json) — เก็บข้อความเดิมทุก byte
- [ต้นฉบับคำตอบ MCP รอบนี้](cases/01-investigate-10.70.0.66/support/agent-answer-mcp-2026-09-08-original.txt)
- [ผลประเมินของ Codex และวิธี cross-check โดยไม่ใช้ MCP](cases/01-investigate-10.70.0.66/verification/README.md)
- [ตัววัดจากไฟล์จริง](cases/01-investigate-10.70.0.66/verification/check_raw.py) และ [คำสั่งตรวจซ้ำจากหลักฐานจริงโดยไม่ใช้ผลตรวจเดิม](cases/01-investigate-10.70.0.66/verification/recheck.py)
- [ทะเบียนที่มา/ไฟล์ที่คัดลอก](cases/01-investigate-10.70.0.66/PROVENANCE.json)
- [เหตุผลและหลักฐานรองรับการแก้โจทย์](cases/01-investigate-10.70.0.66/QUESTION-CHANGELOG.md)
- [วิธีตรวจซ้ำและผลวัดของ NF-01-v2](cases/01-investigate-10.70.0.66/verification/nf-01-v2/README.md)

ที่มาหนังสือ: คัดลอกทั้งไฟล์จาก [2026-Digital-Forensic ณ commit `6513b294d7da434e18123711e4410cbcc54017de`](https://github.com/aekanun2020/2026-Digital-Forensic/blob/6513b294d7da434e18123711e4410cbcc54017de/book/network-forensics-and-log-analysis-th.md) โดยคงเนื้อหา แผนภาพ และบรรณานุกรมตามต้นฉบับ ตัวอย่างในหนังสือเป็นสถานการณ์สมมติแยกจากหลักฐานและเฉลยของโจทย์ 01

- [บันทึกกิจกรรม GCP](cloud-activities/README.md)
- [student-1: คืนบริการที่ IP ใหม่ วันที่ 10 กันยายน](cloud-activities/2026-09-10-001-student-1-restore-new-ip.md)

- [ผลตรวจกลับมาใช้งานหลัง Start VM วันที่ 9 กันยายน](cloud-activities/2026-09-09-001-student-1-restore.md)

- [บันทึกการตั้งค่า VM กลุ่ม 2–4](cloud-activities/2026-09-09-002-configure-cloned-labs.md)

</details>

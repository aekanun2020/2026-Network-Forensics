# โจทย์ 01 — ตรวจสอบกิจกรรมของ 10.70.0.66

[กลับสารบัญหลัก](../../README.md)

1. [โจทย์ NF-01-v2](QUESTION.md) — ระบุ F1–F6, paths และ SHA-256 พร้อมเงื่อนไขการอ้างหลักฐาน; ส่งทั้งหน้าให้ agent
2. [คำตอบต่อโจทย์เดิม](AGENT-ANSWER.md) — คำตอบ Codex ที่ผู้ใช้ส่งมา แก้เฉพาะลิงก์เพื่อเปิดใน GitHub ไม่ใช่ผลรัน v2
3. [คำตอบ cross-check ตาม NF-01-v2](CROSS-CHECK-NF-01-v2.md) — Codex อ่าน local files ใหม่โดยไม่เรียก MCP พร้อม source inventory, claims และ records/packets
4. [ผลตรวจคำตอบและวิธีทำซ้ำ](verification/README.md)

## เอกสารตรวจสอบย้อนกลับ

- [โจทย์เดิม](QUESTION-v1.md) และ [หลักฐานรองรับการแก้โจทย์](QUESTION-CHANGELOG.md)
- [ผลวัดรอบ NF-01-v2 และวิธีทำซ้ำ](verification/nf-01-v2/README.md) และ [คำตอบอ้างอิงเดิม](REFERENCE-ANSWER.md)
- [หลักฐานหกไฟล์](evidence/README.md) และ [manifest ต้นฉบับ](evidence/source-manifest.json)
- [ต้นฉบับคำตอบไม่แก้ไข](support/agent-answer-original.txt)
- [ผล MCP ที่คำตอบเดิมอ้าง](support/mcp/) — ผลที่เก็บไว้จากรอบก่อน ไม่ได้เรียก MCP ใหม่ในการจัดวางครั้งนี้
- [ผลวัดจากการตรวจเดิม](verification/prior/measurements.json), [integrity เดิม](verification/prior/integrity.json), [tcpdump เดิม](verification/prior/tcpdump-target.txt) และ [ยอด tcpdump เดิม](verification/prior/tcpdump-counts.json)
- [ทะเบียน provenance และ SHA-256 ของไฟล์ที่คัดลอก](PROVENANCE.json)

คำว่า “ถูกต้อง” ในเฉลยหมายถึงข้อสรุปที่หลักฐานหกไฟล์นี้รองรับ ภายใต้ขอบเขตที่ระบุ ไม่ใช่การรับรองว่าเกิด C2 การขโมยไฟล์ หรือการยึดเครื่องจริง

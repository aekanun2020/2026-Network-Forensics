# โจทย์ 01 — ตรวจสอบกิจกรรมของ 10.70.0.66

[กลับสารบัญหลัก](../../README.md)

1. [โจทย์](QUESTION.md) — คำถามต้นฉบับและหลักฐานที่ต้องใช้
2. [คำตอบ](AGENT-ANSWER.md) — คำตอบ Codex ที่ผู้ใช้ส่งมา แก้เฉพาะลิงก์เพื่อเปิดใน GitHub
3. [คำตอบที่ถูกต้องสำหรับชุดข้อมูลนี้](REFERENCE-ANSWER.md) — Codex เรียบเรียงจาก raw evidence และผล cross-check พร้อมข้อจำกัด
4. [ผลตรวจคำตอบและวิธีทำซ้ำ](verification/README.md)

## เอกสารตรวจสอบย้อนกลับ

- [หลักฐานหกไฟล์](evidence/README.md) และ [manifest ต้นฉบับ](evidence/source-manifest.json)
- [ต้นฉบับคำตอบไม่แก้ไข](support/agent-answer-original.txt)
- [ผล MCP ที่คำตอบเดิมอ้าง](support/mcp/) — ผลที่เก็บไว้จากรอบก่อน ไม่ได้เรียก MCP ใหม่ในการจัดวางครั้งนี้
- [ผลวัดจากการตรวจเดิม](verification/prior/measurements.json), [integrity เดิม](verification/prior/integrity.json), [tcpdump เดิม](verification/prior/tcpdump-target.txt) และ [ยอด tcpdump เดิม](verification/prior/tcpdump-counts.json)
- [ทะเบียน provenance และ SHA-256 ของไฟล์ที่คัดลอก](PROVENANCE.json)

คำว่า “ถูกต้อง” ในเฉลยหมายถึงข้อสรุปที่หลักฐานหกไฟล์นี้รองรับ ภายใต้ขอบเขตที่ระบุ ไม่ใช่การรับรองว่าเกิด C2 การขโมยไฟล์ หรือการยึดเครื่องจริง

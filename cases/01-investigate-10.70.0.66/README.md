# โจทย์ 01 — ตรวจสอบกิจกรรมของ 10.70.0.66

[กลับสารบัญหลัก](../../README.md)

1. [โจทย์ NF-01-v2](QUESTION.md) — ระบุ F1–F6, paths และ SHA-256 พร้อมเงื่อนไขการอ้างหลักฐาน; ส่งทั้งหน้าให้ agent
2. [คำตอบ Codex ผ่าน MCP — 8 กันยายน 2026](AGENT-ANSWER-MCP-2026-09-08.md) — คำตอบฉบับเต็มที่ส่งก่อนขั้นตอนเทียบเฉลย ตาม [โจทย์ที่ได้รับจริง](support/mcp-2026-09-08/question-original.txt); ไม่ได้รับ NF-01-v2 ครบทั้งหน้า
3. [คำตอบ cross-check ตาม NF-01-v2](CROSS-CHECK-NF-01-v2.md) — Codex อ่าน local files ใหม่โดยไม่เรียก MCP พร้อม source inventory, claims และ records/packets
4. [ผลตรวจคำตอบเดิมและวิธีทำซ้ำ](verification/README.md)

## เอกสารตรวจสอบย้อนกลับ

- [ภาพประกอบเฉลย](images/README.md) และ [ทะเบียนที่มาของภาพ](images/PROVENANCE.md) — เปิดหลังส่งคำตอบ
- [ผลตรวจข้อมูล lab จาก GitHub เทียบกับ QUESTION.md](evidence/REPOSITORY-CHECK-2026-09-08.json) — ตรวจ ZIP และ raw members ทั้งหก
- [หลักฐานจาก MCP รอบ 8 กันยายน 2026](support/mcp-2026-09-08/README.md), [ต้นฉบับคำตอบรอบนี้](support/agent-answer-mcp-2026-09-08-original.txt) และ [provenance รอบนี้](support/mcp-2026-09-08/provenance.json)
- [หลักฐานรองรับการแก้โจทย์](QUESTION-CHANGELOG.md)
- [ผลวัดรอบ NF-01-v2 และวิธีทำซ้ำ](verification/nf-01-v2/README.md)
- [หลักฐานหกไฟล์](evidence/README.md) และ [manifest ต้นฉบับ](evidence/source-manifest.json)
- [ผล MCP ที่คำตอบเดิมอ้าง](support/mcp/) — ผลที่เก็บไว้จากรอบก่อน ไม่ได้เรียก MCP ใหม่ในการจัดวางครั้งนี้
- [ผลวัดจากการตรวจเดิม](verification/prior/measurements.json), [integrity เดิม](verification/prior/integrity.json), [tcpdump เดิม](verification/prior/tcpdump-target.txt) และ [ยอด tcpdump เดิม](verification/prior/tcpdump-counts.json)
- [ทะเบียน provenance และ SHA-256 ของไฟล์ที่คัดลอก](PROVENANCE.json)

คำว่า “ถูกต้อง” ในเฉลยหมายถึงข้อสรุปที่หลักฐานหกไฟล์นี้รองรับ ภายใต้ขอบเขตที่ระบุ ไม่ใช่การรับรองว่าเกิด C2 การขโมยไฟล์ หรือการยึดเครื่องจริง

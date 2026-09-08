# ทะเบียนที่มาของภาพประกอบ NF-01

[กลับหน้าภาพ](README.md) · [สารบัญโจทย์](../README.md) · [หลักฐานหกไฟล์](../evidence/README.md)

ทะเบียนนี้เก็บตัวระบุต้นทางเป็นข้อความสำหรับตรวจย้อนหลัง การอ่านภาพและการเปิดข้อมูล lab ใช้ไฟล์ภายใน `2026-Network-Forensics`

## ตัวระบุต้นทาง

| รายการ | ค่าที่บันทึก |
|---|---|
| Repository ที่คัดลอกภาพและ README | `aekanun2020/2026-Digital-Forensic` |
| Commit ต้นทาง | `3c7a24f7f09991dd78c4b2d6b24e1e841da95efb` |
| README ต้นทาง | `student/agentic-siem/images/README.md` |
| SHA-256 ของ README ต้นทางก่อนปรับ | `d5a39e9635c4fd1b206718a0e3d8935e69821301838b3cc72da916ce9f6a9990` |
| ภาพต้นทาง | `student/agentic-siem/images/incident-overview-files-wide-th.png` |
| Git blob ของภาพต้นทาง | `f3c89cb2ea3778f31bca8fa464d74e6a79cb7dc4` |
| Repository ของชุดสังเคราะห์ที่ README ต้นทางระบุ | `aekanun2020/agentic-security-log-analytics` |
| Commit ของชุดสังเคราะห์ | `bd22468e80f0481c85549266656cfa10faba7879` |
| Directory ของชุดสังเคราะห์ต้นทาง | `sample-data` |

## ไฟล์ภาพที่เก็บในโครงการนี้

- [ภาพต้นฉบับ](incident-overview-files-wide-th.png): 1,536,879 bytes
- SHA-256: `e2d3dc15b2dfa6d57db22b8afa8e113ef5c9b4b1eca7d02a285b9a9ae3ae3bc1`
- ภาพตรงกับ Git blob ต้นทางที่ตรวจไว้ ไม่มีการแก้ pixel ในรอบปรับลิงก์นี้
- README ต้นทางระบุว่าสร้างภาพด้วย imagegen วันที่ 8 กันยายน 2026 เพื่อประกอบข้อมูลสังเคราะห์วันที่ 24 สิงหาคม 2026 UTC ไม่ใช่ภาพจากระบบจริงหรือหลักฐานผลรัน agent

## การปรับเอกสารในโครงการนี้

1. Commit `b008f2fe5dc3186862a66504158cd3ded4932ea7` นำภาพต้นฉบับและสำเนา README เข้ามา พร้อม [Q&A ประเมินภาพโดย Codex](../../../Q&A/2026-09-08-nf01-incident-image-review.md)
2. รอบปรับวันที่ 8 กันยายน 2026 เปลี่ยนลิงก์ในหน้าภาพให้ใช้เอกสารและ ZIP ภายในโครงการ ลดตาราง ZIP เหลือชุดเดียว และเพิ่มคำอธิบายผลตรวจที่มีอยู่จริง ไม่อ้างว่า README ฉบับปรับยังตรงต้นทางทุก byte
3. เพิ่มคำแก้ไขในการอ่านภาพ โดยคงภาพเดิม: DNS server คือ `10.70.0.53` ส่วน `203.0.113.66` คือ DNS answer; รหัสหลักฐานของ outbound ต้องเป็น F1/F3/F4/F5
4. แยกผลวัด NF-01-v2 ที่เก็บในโครงการนี้ออกจาก `fixture-facts.json` และ `view-correlation.json` ของต้นทาง ไม่อ้างว่าเป็นไฟล์เดียวกันหรือเป็นการรัน investigator ใหม่
5. ตรวจข้อมูล lab จาก GitHub ของโครงการนี้ใหม่ทั้งหก archives และ raw members เทียบกับโจทย์ ดู [ผลตรวจตัวตนและการมีอยู่ของหลักฐาน](../evidence/REPOSITORY-CHECK-2026-09-08.json)

## ขอบเขตของผลตรวจ

ผลตรวจไฟล์ยืนยันหลักฐานใน repository ณ commit ที่บันทึกไว้ ใช้ [QUESTION.md](../QUESTION.md) กำหนดชื่อ ขนาด SHA-256 และ MCP virtual paths โดย [source manifest](../evidence/source-manifest.json) ยังคงต้นฉบับเพื่อรักษา hash ที่โจทย์กำหนด ค่า `sample_directory` ใน manifest เป็นข้อมูลต้นทางเก่า; ตำแหน่ง ZIP ที่ใช้งานในโครงการนี้ให้เปิดจาก [ทะเบียนหลักฐาน](../evidence/README.md)

ผลนี้ไม่ยืนยันการติดตั้งหรือสถานะ Spark/HDFS MCP ปัจจุบัน และไม่ยืนยันว่าพฤติกรรมในข้อมูลสังเคราะห์เป็นเหตุโจมตีจริง

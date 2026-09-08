# หลักฐานรองรับการแก้โจทย์เป็น NF-01-v2

[โจทย์ที่ใช้ปัจจุบัน](QUESTION.md) · [โจทย์เดิมที่เก็บตรงต้นฉบับ](QUESTION-v1.md) · [สารบัญโจทย์](README.md)

## เหตุผลที่แก้

คำถามเดิมระบุ IP และ “หลักฐานทั้งหกไฟล์” โดยไม่มีรายชื่อหรือ hash ในข้อความคำถาม แม้หน้าเอกสารประกอบจะมีลิงก์และ directory แต่หากส่งเฉพาะคำถามย่อให้ agent ก็ไม่เพียงพอจะกำหนดชุดข้อมูลแน่นอน การตัดสินว่าเลือกข้อมูลผิดจึงต้องตรวจว่า agent ได้รับขอบเขตอะไรจริงก่อน

repository ต้นทางมีหลาย fixtures ที่ใช้ IP 10.70.0.66: [manifest ชุดสามแหล่ง coherent-course](https://github.com/aekanun2020/2026-Digital-Forensic/blob/3c7a24f7f09991dd78c4b2d6b24e1e841da95efb/student/agentic-siem/source/sample-data/coherent-course-scenario.manifest.json) และ [manifest ชุดหกไฟล์ PCAP/views ของ case นี้](evidence/source-manifest.json) การใช้ IP หรือ MCP server เดียวกันจึงไม่ใช่ตัวตัดสินว่าเป็น raw files เดียวกัน

## สิ่งที่ระบุให้แน่นอนใน v2

ปรับเพิ่มเติมให้ข้อความคำถามข้อ 1 แสดงชื่อไฟล์และ virtual path เต็มทั้งหกโดยตรง รหัส F1–F6 คงไว้เป็นชื่อย่อในตาราง hashes เท่านั้น ผู้เรียนไม่ต้องแปลรหัสย่อเพื่อทราบว่าจะอ่านไฟล์ใด

| ข้อกำหนด | หลักฐาน/เหตุผลที่ตรวจได้ |
|---|---|
| ชื่อ raw files, bytes, SHA-256 ครบ F1–F6 ในตัวโจทย์ | คัดจาก source manifest และคำนวณตรวจ ZIP/member จริงทั้งหกไฟล์อีกครั้งเมื่อ 8 กันยายน 2026; ตรงทุกไฟล์ |
| ตรึง source manifest และ ZIP inventory ด้วย commit | ใช้ commit 58a7c4c56726b178737e9f019105218c8cbfb2ee ของ repo นี้ ป้องกันการเปลี่ยนชุดโดยไม่รู้ตัวเมื่อ branch เคลื่อน |
| แยก hash ของ ZIP กับ raw member | manifest มี archive_sha256 และ sha256 เป็นคนละ field; source inventory ต้องแสดงค่าที่อ่าน/คำนวณจริง |
| ระบุ HDFS virtual/physical และ local archive directory | ใช้ paths ใน manifest กับตำแหน่ง ZIPs จริงใน repo ไม่ใช้ sample_directory เก่าของ repo ต้นทางเป็น local path ใหม่ |
| ไม่ป้อนโดเมน จำนวน peers/flows หรือยอด bytes ของคำตอบ | v2 ให้ค้นจากข้อมูลหลังตรวจ identity แทนการชี้นำผลที่ต้องพบ |
| บังคับ references ที่ย้อนกลับไป raw records/packets | ทุก claim ต้องมี locator, fields/payload และวิธีวัด โดยยอดรวมต้องบอกขอบเขตและทิศทาง |
| แยกผลเดิมกับรอบใหม่ | คำตอบ Codex ที่เก็บอยู่เกิดก่อน NF-01-v2 ไม่มีการเปลี่ยนให้เป็นผลทดสอบ v2 |

SHA-256 ของ source-manifest.json ที่ตรวจครั้งนี้: `f87a71cf860628eda39cb0201b01f958b06ef2c1f70e44b11efc9aa4088fe034` การแก้ครั้งนี้ไม่เปลี่ยน ZIPs, raw identities, คำตอบต้นฉบับ, ผล MCP เดิม หรือผลวัดที่บันทึกไว้ และยังไม่ได้รัน investigator เปรียบเทียบ agent ด้วยโจทย์ v2

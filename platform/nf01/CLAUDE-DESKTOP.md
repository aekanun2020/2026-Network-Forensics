# เชื่อม Claude Desktop กับ NF-01 MCP

## URL สำหรับ lab

`https://34-142-187-162.sslip.io/mcp`

ชื่อ connector: **NF-01 Spark HDFS**

บริการนี้ใช้ข้อมูลและสิทธิ์ร่วมกันตามรูปแบบที่ผู้สอนกำหนด ไม่ต้องกรอก OAuth Client ID, Client Secret หรือ API key ของ MCP

## เพิ่ม connector

1. เปิด Claude แล้วไปที่ **Customize → Connectors**
2. กด **+ → Add custom connector**
3. กรอกชื่อ **NF-01 Spark HDFS** และ URL ข้างต้น แล้วกด **Add**
4. เปิดแชตใหม่ กด **+ → Connectors** แล้วเปิดใช้งาน **NF-01 Spark HDFS**

สำหรับบัญชี Team/Enterprise ให้เจ้าขององค์กรเพิ่ม connector ใน **Organization settings → Connectors → Add → Custom → Web** ก่อน สมาชิกจึงเชื่อมใช้งานได้

ขั้นตอนอ้างอิง [คู่มือ remote MCP ของ Claude](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) ตรวจเมื่อ 8 กันยายน 2026; ชื่อเมนูอาจต่างกันตามรุ่นแอป บริการนี้ไม่ได้ตั้ง OAuth จึงเว้น Advanced settings ด้าน OAuth ไว้

## ตรวจการเชื่อมต่อก่อนเริ่มโจทย์

ส่งข้อความนี้ในแชตที่เปิด connector แล้ว:

> ใช้ connector NF-01 Spark HDFS เรียก hdfs_stat และ hdfs_sha256 สำหรับไฟล์ /student/agentic-siem/incident-lab/input/coherent-pcap-zeek-dns-120.jsonl แล้วรายงานขนาดและ SHA-256 จากผลเครื่องมือจริง ยังไม่ต้องวิเคราะห์เหตุการณ์

ตรวจผลกับ [ทะเบียนขนาดและ SHA-256](evidence-inventory.json) จากนั้นเริ่มแชต lab ใหม่และส่ง [QUESTION.md ฉบับเต็ม](../../cases/01-investigate-10.70.0.66/QUESTION.md) เพื่อให้ใช้ขอบเขตเดียวกันทั้งกลุ่ม

ผู้เรียน 4 คนใช้ URL เดียวกันได้ ระบบรับงาน Spark รวมไม่เกิน 8 งาน และให้ทำงานพร้อมกันไม่เกิน 2 งาน งานที่เหลือมีสถานะ QUEUED ให้รอผลโดยอ้างอิง job_id เดิม และใช้ชื่อไฟล์งานที่มีรหัสผู้เรียนเพื่อหลีกเลี่ยงการใช้ชื่อซ้ำ

## ขอบเขตการตรวจรับ

[ผลทดสอบจากเครื่องภายนอก VM](../../cloud-activities/evidence/2026-09-08-public-mcp-verification.json) เป็นการตรวจโดย MCP SDK จริง ไม่มีการเรียกโมเดล ไม่ใช่ผลทดสอบภายในบัญชี Claude Desktop ของผู้เรียน ต้องทดลองเชื่อมตามขั้นตอนข้างต้นก่อนเริ่มเรียน

URL ผูกกับ Static IP `34.142.187.162` ซึ่งตรวจยืนยันการจองแล้ววันที่ 9 กันยายน 2026 เมื่อคง IP นี้ไว้กับ VM จะใช้ URL เดิมหลัง Start ได้ โดยต้องรอให้บริการพร้อมก่อนเชื่อม

# MCP endpoints สำหรับผู้เรียน 4 กลุ่ม

แต่ละ VM รองรับกลุ่มละ 4 คน ใช้ข้อมูลและคิว Spark แยกเครื่อง ทุก URL ใช้การเข้าถึงแบบไม่มีล็อกอินตามที่ผู้สอนกำหนด จึงไม่ใช่การบังคับสิทธิ์สมาชิกตามกลุ่ม

| กลุ่ม | VM | MCP URL | ผลตรวจ MCP |
|---|---|---|---|
| 1 | student-1 | `https://34-142-187-162.sslip.io/mcp` | [ผ่านก่อนตั้งค่าเครื่องสำเนา](../../cloud-activities/evidence/2026-09-09-public-mcp-verification.json) |
| 2 | student-2 | `https://34-142-220-235.sslip.io/mcp` | [ผ่าน](../../cloud-activities/evidence/2026-09-09-student-2-public-mcp-verification.json) |
| 3 | student-3 | `https://34-177-83-99.sslip.io/mcp` | [ผ่าน](../../cloud-activities/evidence/2026-09-09-student-3-public-mcp-verification.json) |
| 4 | student-4 | `https://35-240-216-66.sslip.io/mcp` | [ผ่าน](../../cloud-activities/evidence/2026-09-09-student-4-public-mcp-verification.json) |

## การเชื่อม Claude Desktop

ใช้ **Customize → Connectors → + → Add custom connector** แล้วใส่ URL ของกลุ่มตนเอง จากนั้นเปิด connector ในแชต ไม่ต้องกรอก OAuth Client ID/Secret

- [กลุ่ม 1](CLAUDE-DESKTOP.md)
- [กลุ่ม 2](instances/student-2/CLAUDE-DESKTOP.md)
- [กลุ่ม 3](instances/student-3/CLAUDE-DESKTOP.md)
- [กลุ่ม 4](instances/student-4/CLAUDE-DESKTOP.md)

อ่าน [โจทย์ฉบับเต็ม](../../cases/01-investigate-10.70.0.66/QUESTION.md) แล้วใช้เฉพาะหลักฐานหกไฟล์ตามโจทย์ ขนาดและ SHA-256 อ้างอิง [ทะเบียนหลักฐาน](evidence-inventory.json)

## ผู้ดูแลระบบ

- [student-2: config และคู่มือ](instances/student-2/README.md)
- [student-3: config และคู่มือ](instances/student-3/README.md)
- [student-4: config และคู่มือ](instances/student-4/README.md)
- [ทะเบียนเครื่องและ hashes ของ config](instances/manifest.json)
- [บันทึก cloud-activities](../../cloud-activities/2026-09-09-002-configure-cloned-labs.md)

IP ของ student-1 จองเป็น Static IP แล้ว ส่วนสามเครื่องใหม่ยังไม่พบการจองใน inventory ที่ตรวจ หากต้องการให้ URL คงเดิมหลัง Stop/Start ให้จอง IP ปัจจุบันก่อนหยุด VM

คิว Spark แยกตาม VM: ทำงานพร้อมกันได้สูงสุด 2 งาน และรับรวมสูงสุด 8 งานต่อเครื่อง ตั้งชื่อไฟล์งานให้มีรหัสผู้เรียนเพื่อหลีกเลี่ยงชื่อซ้ำภายในกลุ่ม

ผลจาก MCP SDK เป็นการตรวจโปรโตคอลและการประมวลผลจริงโดยไม่เรียกโมเดล ไม่ใช่ผลทดสอบบัญชี Claude Desktop ของผู้เรียน งานและประวัติที่ติดมากับ machine image ยังคงอยู่และไม่ถือว่าเป็นผลวิเคราะห์ใหม่ของแต่ละกลุ่ม

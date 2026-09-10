# Native binary upload for the deployed student-1 MCP

เพิ่ม `hdfs_upload_file` ในบริการจริงที่ `https://35-186-155-169.sslip.io/mcp` สำหรับส่ง binary จาก client เข้า HDFS โดยไม่ต้องวางใน VM imports ก่อน

- [บันทึกการนำเข้าและ deployment](../../2026-09-10-002-psexec-import-and-binary-mcp.md)
- [Source patch ของ server จริง](server.py.patch)
- [Client ที่อ่านไฟล์ local และเรียก MCP โดยตรง](upload_file.py)
- [การทดสอบกับไฟล์จริงผ่าน public MCP](verify_binary_upload.py)
- [Baseline ขนาดและ SHA-256 ของ F1–F6](nf01-integrity-baseline.json)
- [ผลทดสอบจริง](../../evidence/2026-09-10-native-binary-upload-verification.json)
- [ผลเรียก client หลังตั้งหลักฐานเป็นอ่านอย่างเดียว](../../evidence/2026-09-10-binary-upload-client-replay.json)

## Tool arguments

| Argument | ความหมาย |
|---|---|
| `destination` | virtual HDFS path ไม่เติม `/mcp` และต้องมีสิทธิ์เขียนปลายทาง |
| `content_base64` | Base64 มาตรฐานของ bytes จริง ไม่มี data-URL prefix หรือ whitespace |
| `expected_bytes` | ขนาดต้นทางที่ client ตรวจเอง สูงสุด 33,554,432 bytes (32 MiB) |
| `expected_sha256` | SHA-256 ต้นทาง 64 ตัว hexadecimal |

Tool ตรวจขนาด/hash ก่อนเขียน จากนั้นใช้กระบวนการนำเข้าเดียวกับ `hdfs_import_file`: เขียน temporary file ใน HDFS ตรวจ bytes/hash แล้ว rename ไปปลายทาง การเรียกซ้ำกับข้อมูลเดิมคืน `reused=true`; ข้อมูลต่างจากไฟล์เดิมถูกปฏิเสธและไม่มีตัวเลือก overwrite สำหรับ tool ใหม่นี้

Staging อยู่ชั่วคราวใน state volume เดิม; `/imports` ยังคง mount แบบอ่านอย่างเดียว สำเร็จแล้วคืน `destination_verified=true`, physical `destination` สำหรับ Spark และ `virtual_path` สำหรับ HDFS tools

Imports/uploads ทำงานทีละรายการใน MCP process นี้ หาก busy ให้รอจนรายการก่อนจบก่อน retry; ไม่มีการรับประกันข้ามหลาย replica หรือ writer อื่น Filesystem permissions เดิมยังมีผล ไม่มีการให้ tool ยกระดับสิทธิ์เอง

## ใช้ client

Client ต้องอ่านไฟล์ต้นทางบนเครื่องตนเองได้ และมี Python MCP SDK (ทดสอบจริงด้วย 1.30.0) ไม่เรียกโมเดลหรือส่งไฟล์ผ่าน SCP ตัวอย่างใช้ path ของไฟล์ที่ผู้ใช้ให้และปลายทางที่ตรวจแล้ว:

```sh
python upload_file.py \
  --endpoint https://35-186-155-169.sslip.io/mcp \
  --source /Users/grizzlymacbookpro/Downloads/temp_extract_dir/psexec-hunt.pcapng \
  --destination /student/agentic-siem/additional-evidence/psexec-hunt/psexec-hunt.pcapng
```

ไฟล์นี้นำเข้าไว้แล้ว คำสั่งเดียวกันจึงเป็นการตรวจการเรียกซ้ำกับ bytes เดิม ส่วนไฟล์ใหม่ต้องใช้ directory ที่บัญชี MCP เขียนได้ Client/แอปอาจจำกัดขนาด request ต่ำกว่าเพดาน server การแนบไฟล์เข้า Claude Desktop เพียงอย่างเดียวไม่ได้เป็นหลักฐานว่า client ส่ง binary เข้า tool ได้; ผลที่บันทึกเป็นการทดสอบด้วย MCP SDK จริง

## Source and verification provenance

Patch อ้างอิง `/opt/nf01/mcp-server/server.py` ที่อ่านจาก VM จริง ไม่ดึง implementation จาก branch ที่คาดเดา และไม่คืน directory `platform/nf01` ที่ผู้ใช้ลบไปแล้ว

- Baseline server SHA-256: `1634b597824dd473fd2c7ec049c388614d0e4f3a300382788cb1471a38e2420c`
- Final server SHA-256: `51e8981556a8ab6656d89e6f2220081a93243b8de65ec81ecab0b6ceb3b1b62c`
- Live SDK: `mcp 1.30.0`; ใช้ constructor option `max_request_body_size=44804780` เพื่อรองรับ Base64+JSON ของไฟล์ 32 MiB โดยยังมีเพดาน request
- NF-01 baseline: exact historical file `platform/nf01/evidence-inventory.json` from verified local checkout of destination repository commit `1b6a05c873a13b0af2586f1b2119a61efe378626`, with no working-tree difference; SHA-256 `ac0e6fc0a5ded67dd51300057605599d541a37b6fd1a7936e8ecde4ba531bbc9`.

Verifier ใช้ capture ที่ผู้ใช้ให้ทั้งไฟล์สำหรับ positive upload/replay และ bytes ส่วนต้นของไฟล์เดียวกันสำหรับ conflict/validation tests โดยไม่บันทึก payload หรือ capture ลง repository ผลล้มเหลวครั้งแรกและการแก้ root cause HTTP 413 อยู่ใน activity record; ไม่รวมเป็นผลผ่าน

Run verifier เฉพาะเมื่อได้รับอนุญาตให้สร้าง/ลบสำเนาทดสอบ และบันทึก GCP activity ไว้ก่อน ปลายทางการทดสอบต้องเขียนได้; directory หลักฐานที่ seal แล้วต้องไม่เปิดสิทธิ์อัตโนมัติเพื่อรันทดสอบซ้ำ

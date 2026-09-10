# รายงานลำดับการครอบครองและจัดการพยานหลักฐานดิจิทัล (Chain of Custody Report)

| รายการ | รายละเอียด |
|---|---|
| รหัสรายงาน | COC-PSEXEC-20260910-01 — กำหนดขึ้นสำหรับรายงานนี้ |
| รหัสรายการหลักฐาน | E-PSEXEC-001 — กำหนดขึ้นสำหรับรายงานนี้ ไม่ใช่เลขของผู้เก็บต้นฉบับ |
| ชื่อรายการ | psexec-hunt.pcapng |
| เลขคดี / หน่วยงานเจ้าของคดี | ยังไม่ได้รับข้อมูล |
| วันที่จัดทำ | 2026-09-10T21:42:56+07:00 |
| ผู้จัดทำและผู้ประเมิน | Codex agent; จัดทำจากบทสนทนา บันทึกปฏิบัติงาน และผล tools จริง ไม่ใช่ลายมือชื่อของบุคคล |
| สถานะ | รายงานย้อนหลังสำหรับงานห้องปฏิบัติการ ยังไม่มีการลงนามรับรองโดยผู้ส่ง ผู้รับ หรือผู้ดูแลหลักฐานที่เป็นบุคคล |
| ขอบเขต | ไฟล์ที่ผู้ใช้ระบุบน Mac → สำเนาบน VM → สำเนาใน HDFS → การตรวจด้วย MCP → สถานะ ณ เวลาจัดทำรายงาน |

## 1. ผลการตรวจและขอบเขตการรับรอง

ตรวจซ้ำ ณ **2026-09-10T21:40:33+07:00** พบว่าไฟล์ที่ผู้ใช้ระบุบน Mac และสำเนาที่อ่านจาก HDFS มีขนาด **10,027,488 bytes** และ SHA-256 ตรงกัน รวมถึงตรงกับค่าที่บันทึกไว้เมื่อมีการนำเข้า ดู [ผลตรวจปัจจุบัน](support/integrity-at-report.json)

ผลนี้รองรับความตรงกันของเนื้อหาไฟล์ ณ จุดตรวจที่บันทึกไว้ ไม่ได้พิสูจน์ประวัติการครอบครองทุกช่วงเวลา ความแท้จริงของเหตุการณ์ใน capture หรือวิธีได้มาของไฟล์ก่อนผู้ใช้ส่ง path มา ผู้จัดทำจึง **ไม่รับรองว่า chain of custody ครบถ้วนตั้งแต่การเก็บต้นฉบับ** และไม่วินิจฉัยการรับฟังเป็นพยานหลักฐานทางกฎหมาย

รายงานใช้แนวทางบันทึกผู้เกี่ยวข้อง เวลา การเคลื่อนย้าย วัตถุประสงค์ และการรักษาความครบถ้วนของหลักฐานตาม [นิยาม Chain of Custody ของ NIST](https://csrc.nist.gov/glossary/term/chain_of_custody) และ [NIST SP 800-86](https://csrc.nist.gov/pubs/sp/800/86/final) การอ้างแนวทางเหล่านี้ไม่ใช่การรับรองว่ากระบวนการใน lab ผ่านข้อกำหนดทุกประการ

## 2. การระบุหลักฐานและจุดจัดเก็บ

**SHA-256 ของเนื้อหาไฟล์ที่ตรวจตรงกัน:**

```text
85c1ded1fea23cb9277604f7b26a520718eed47445e4624182beb88c2388357f
```

| สำเนา / ตำแหน่ง | รายละเอียดและสถานะ |
|---|---|
| ไฟล์ที่ผู้ใช้ระบุบน Mac | `/Users/grizzlymacbookpro/Downloads/temp_extract_dir/psexec-hunt.pcapng` — ตรวจ hash ปัจจุบันแล้ว; ไม่ยืนยันว่าเป็นต้นฉบับที่เก็บจากระบบเป้าหมาย และไม่ได้ตรวจรับรอง write protection ของ Mac |
| สำเนาสำหรับนำเข้าบน VM | `/opt/nf01/imports/psexec-hunt.pcapng` — บันทึกเดิมยืนยัน root:root, mode 0444 และ hash ตรง; ไม่ได้ SSH ตรวจสำเนานี้ซ้ำขณะเขียนรายงาน |
| MCP virtual path | `/student/agentic-siem/additional-evidence/psexec-hunt/psexec-hunt.pcapng` |
| Physical HDFS path | `/mcp/student/agentic-siem/additional-evidence/psexec-hunt/psexec-hunt.pcapng` |
| HDFS file metadata ปัจจุบัน | FILE; fileId 16404; root:supergroup; permission 0444; replication 2; length 10027488 |
| HDFS evidence directory ปัจจุบัน | `/mcp/student/agentic-siem/additional-evidence/psexec-hunt`; root:supergroup; permission 0555; childrenNum 1 |
| สภาพแวดล้อมที่ใช้นำเข้า | GCP project `bigdatainpractice1`; VM `student-1`; zone `asia-southeast1-a` ตาม activity record |
| MCP endpoint ที่ตรวจปัจจุบัน | `https://35-186-155-169.sslip.io/mcp` |
| ประเภทการเก็บ | สำเนาเนื้อหาไฟล์ PCAPNG ไม่ใช่ forensic image ของดิสก์ทั้งลูก; ไม่มีข้อยืนยันว่ารักษา filesystem metadata ของต้นฉบับครบ |

HDFS replication 2 เป็นคุณสมบัติการจัดเก็บที่รายงานโดยระบบ ไม่ใช่หลักฐานว่ามีสำเนาสำรองอิสระคนละเครื่อง/คนละสถานที่ และไม่ใช่การลงลายมือชื่อรับส่งสองครั้ง

## 3. บุคคล บัญชี และบทบาทที่ระบุได้

| ผู้เกี่ยวข้อง / identity | บทบาทที่มีหลักฐาน | สิ่งที่ยังไม่ทราบ |
|---|---|---|
| ผู้ใช้ในบทสนทนา | ระบุไฟล์และอนุญาตให้นำเข้า HDFS วางใน VM และเพิ่ม MCP tool | ชื่อผู้ส่งตามเอกสาร หน่วยงาน อำนาจเก็บหลักฐาน และลายมือชื่อส่งมอบ |
| Codex agent | ดำเนินการโอน นำเข้า ตรวจสอบ และวิเคราะห์ตามคำสั่งผู้ใช้; ผู้จัดทำรายงานนี้ | ไม่ใช่บุคคลผู้ลงนามหรือผู้ครอบครองทางกายภาพ |
| `thaimcpagent@gmail.com` | บัญชี gcloud ที่ตรวจว่าใช้งานในช่วงวางไฟล์/ปรับ VM; configuration `bigdatainpractice` | ไม่ใช่หลักฐานระบุตัวบุคคลสำหรับทุก MCP request |
| `spark` | identity ของ MCP ใน HDFS ขณะนำเข้าและประมวลผล | เป็น service identity ไม่ใช่ชื่อผู้สืบสวนแต่ละราย |
| `root:supergroup` | เจ้าของไฟล์/โฟลเดอร์ HDFS หลังตั้ง read-only | ไม่ใช่ชื่อผู้รับมอบหลักฐานที่เป็นบุคคล |

คำสั่งที่รองรับขอบเขตงาน ได้แก่ “นำเข้าไฟล์นี้สู่ hdfs ให้หน่อยได้ปะ เสนอ dir มาด้วย”, “อยากให้ใช้ mcp tool นำเข้า”, “เอาไปวางให้หน่อย แต่ประเด็นคงต้องสร้าง mcp tool เพิ่มด้วย” และ “โปรดใช้ mcp tool ในการวิเคราะห์เพื่อตอบ ทั้ง 7 ข้อนะ” เป็นการอนุญาตดำเนินงานในบทสนทนา ไม่ใช่แบบฟอร์มส่งมอบที่ลงนามแล้ว

## 4. ทะเบียนลำดับการจัดการและเคลื่อนย้าย

เวลาในตารางเป็นวันที่ **10 กันยายน 2026 เขตเวลา Asia/Bangkok (UTC+07:00)** เว้นแต่ระบุอย่างอื่น ช่วงเวลาจาก JSON เป็นเวลาที่ client บันทึกการทำงาน; เวลา “บันทึก” จาก Markdown เป็นเวลาเขียนบันทึก ไม่ควรตีความเป็นเวลาโอนจริงที่แม่นยำทุกขั้นตอน ไม่มีผลยืนยันความเที่ยงตรงหรือการเทียบเวลาของทุกระบบ

| ลำดับ | เวลา / ชนิดเวลา | จาก → ไป / การจัดการ | ผู้ดำเนินการและเครื่องมือ | ผล / แหล่งอ้างอิง |
|---|---|---|---|---|
| C01 | ก่อน 15:33:34; เวลาเก็บและส่งไฟล์ต้นทางไม่ทราบ | ผู้ใช้ระบุไฟล์ใน Mac; ตรวจขนาด/hash เริ่มต้น | ผู้ใช้ระบุ path; Codex ตรวจไฟล์ | ได้ค่าอ้างอิงข้างต้น; ไม่มี acquisition log ก่อนจุดนี้ [R1] |
| C02 | 15:33:34 เวลาเปิด activity record | บันทึกแผนและ authorization ก่อนเปลี่ยน GCP | Codex | บันทึก source, destination, hash และขอบเขต [R1] |
| C03 | บันทึกว่าเสร็จ 15:35:23 | Mac → VM operator home → `/opt/nf01/imports/psexec-hunt.pcapng` | Codex; gcloud SCP ผ่าน IAP/SSH; `install` | ตรวจ bytes/hash ตรง; mode 0444; imports mount read-only [R1] ไม่มี signed handoff |
| C04 | เริ่ม 15:35:22.995259; บันทึก failure 15:36:13 | พยายาม imports → HDFS | Codex; MCP `hdfs_import_file` | ล้มเหลวที่ mkdir เพราะ `spark` ไม่มีสิทธิ์; ไม่เผยแพร่ capture ปลายทาง [R2] เวลาบันทึก C03/C04 ไม่ใช่ลำดับเวลาแต่ละคำสั่ง |
| C05 | หลัง C04 ก่อน 15:37:39; เวลาแน่นอนไม่ได้บันทึก | เตรียมเฉพาะ HDFS directory ใหม่ | Codex; admin CLI ใน NameNode | ให้ `spark` เขียนใน directory ใหม่; ไม่เปลี่ยน directory NF-01 เดิม [R1] |
| C06 | ช่วง 15:37:39.306849–15:37:58.764188; เป็นเวลาทั้งชุดตรวจ | imports → HDFS canonical file | Codex; MCP `hdfs_import_file`, `hdfs_stat`, `hdfs_sha256` | `overwrite=false`, `reused=false`, source stable และ destination verified; hash/bytes ตรง [R3] |
| C07 | MCP เริ่มใหม่ 15:38:59.999249 | เปลี่ยน implementation ของ MCP เพื่อเพิ่ม binary upload; เก็บ backup code/image | Codex; Docker Compose build/recreate เฉพาะ MCP | มีการเปลี่ยนเครื่องมือระหว่างการจัดการหลักฐาน; บันทึก hashes และการตรวจหลังเปลี่ยน [R1,R7] |
| C08 | เริ่มการทดสอบรอบแรก 15:39:40.220820 | ทดลองส่ง binary ผ่าน tool ใหม่ | Codex; MCP `hdfs_upload_file` | request ถูก SDK ปฏิเสธ HTTP 413 ก่อน tool ทำงาน; client เห็น ReadError; ไม่พบไฟล์ทดสอบจากรอบนี้ ตรวจและแก้ body limit ก่อน retry [R4,R1] |
| C08b | MCP เริ่มใหม่ 15:42:10.831178 | แก้ขนาด HTTP body limit หลังพบ HTTP 413 และ rebuild/recreate เฉพาะ MCP อีกครั้ง | Codex; Docker Compose | ใช้ตัวเลือกที่ SDK รองรับ; บันทึก final source/image hash และทดสอบใหม่ [R1,R7] |
| C09 | 15:42:37.424146–15:42:51.858568 | Mac bytes → HDFS สำเนาทดสอบท้ายชื่อ `.mcp-upload-verification-20260910` | Codex; MCP `hdfs_upload_file` | รับ Base64 ตรวจ expected bytes/hash แล้วเผยแพร่สำเนาทดสอบ; อ่าน hash จาก HDFS ยืนยันซ้ำ [R5] |
| C10 | 15:42:54.343109–15:43:01.531050 | เรียก upload ซ้ำกับสำเนาทดสอบ | Codex; MCP `hdfs_upload_file` | `reused=true`; ไม่แทนไฟล์ด้วยเนื้อหาต่างกัน; negative tests แยกบันทึก [R5] |
| C11 | 15:43:13.374464–15:43:13.467911 | ลบเฉพาะสำเนาทดสอบ | Codex; MCP `hdfs_delete` | ตรวจยืนยันสำเนาทดสอบหาย; canonical file ยังอยู่และ hash ตรง [R5] |
| C12 | บันทึกว่าเสร็จ 15:44:39 | ตั้ง canonical HDFS file 0444 และ directory 0555; ลบไฟล์ส่งผ่านชั่วคราวใน VM home | Codex; HDFS admin CLI / shell | เก็บ VM imports file; ไม่เหลือ binary-upload staging ณ จุดตรวจ [R1] ไม่มีการลบหลักฐาน canonical |
| C13 | บันทึกว่าเสร็จ 15:45:21; replay JSON ไม่มีเวลาในตัวเอง | ตรวจการส่งซ้ำหลังตั้ง read-only | Codex; native MCP client → `hdfs_upload_file` | `reused=true`, destination verified, hash ตรง, staging removed [R6,R1] |
| C14 | หลังนำเข้า ก่อนรายงาน; timestamp การเรียกแต่ละครั้งไม่ถูกเก็บใน result files | อ่าน HDFS เพื่อวิเคราะห์คำถาม 7 ข้อ → MCP results → local temporary JSONL | Codex; `hdfs_pcap_packets`; TShark ใน server; สคริปต์ local แสดง fields/ข้อความจากผล MCP | ผลที่เก็บทุก call อ้าง source hash เดียวกัน; index แยก capture timestamps ออกจากเวลาวิเคราะห์ [R8] |
| C15 | 2026-09-10T21:40:33+07:00 เวลาชุดตรวจสิ้นสุด | ตรวจ local source และ HDFS ซ้ำเพื่อจัดทำ CoC | Codex; local SHA-256; MCP `hdfs_stat` / `hdfs_sha256` | เนื้อหา 10027488 bytes และ SHA-256 ตรง; root ownership/0444 และ directory 0555 ยังปรากฏ [R9] |

## 5. เครื่องมือ วิธีใช้ และผลที่ได้

| เครื่องมือ | หน้าที่จริง | ผลต่อหลักฐาน / ข้อจำกัด |
|---|---|---|
| gcloud SCP ผ่าน IAP/SSH และ `install` | วางสำเนาจาก Mac ใน VM imports | ขั้น Mac → VM ไม่ได้ทำด้วย MCP; เก็บและตรวจเนื้อหาไฟล์ ไม่มีรายงานว่าเป็น disk imaging |
| `hdfs_import_file` | นำไฟล์จาก imports ไป HDFS canonical path | tool รายงานตรวจ source stable / destination hash และ publish ด้วย rename; ผลสำเร็จใช้ `overwrite=false` |
| `hdfs_upload_file` | ทดสอบส่ง binary โดย MCP โดยตรง และทดสอบ replay | cap 32 MiB; ใช้ staging ชั่วคราว; ไม่ใช่ tool ที่ใช้สร้าง canonical file ครั้งแรก |
| `hdfs_stat` | อ่านขนาด owner permissions replication และ metadata | metadata เช่น accessTime อาจเปลี่ยนจากการอ่าน ไม่ใช่เวลารับมอบหรือเวลาจับแพ็กเก็ต |
| `hdfs_sha256` | อ่านทั้งไฟล์ใน HDFS และคำนวณ SHA-256 | ยืนยัน bytes/hash ของจุดตรวจ ไม่ใช่การบันทึกตัวบุคคลผู้เข้าถึงย้อนหลังทุกคน |
| `hdfs_pcap_packets` | อ่าน capture ผ่าน HDFS ไป temporary file บน server แล้วเรียก TShark; ส่งผล JSON ที่มี packet references | อ่าน/วิเคราะห์สำเนา ไม่แก้ canonical bytes ตามเส้นทางการทำงานที่ตรวจ; มี temporary analysis copy ระหว่าง call ไม่มีชื่อ temp directory/เวลา cleanup ราย call ที่ถูกเก็บไว้ในหลักฐานประกอบนี้ |
| TShark | ถอดโครงสร้าง packet ตาม display filters ใน MCP server | ผล tool ระบุ `dissector=tshark`; version string ของ TShark ณ การวิเคราะห์ไม่ได้เก็บไว้ จึงไม่กำหนดเวอร์ชันขึ้นเอง |
| Python local | คำนวณ hash ต้นทาง จัดข้อมูลจาก MCP และสร้างรายงาน/index | การวิเคราะห์ 7 ข้อใช้ payload ที่ MCP คืนมา ไม่ได้ใช้ local TShark วิเคราะห์ PCAP แทน MCP |
| Codex agent | ประเมินความหมาย เชื่อม packet requests/responses และตอบคำถาม | ไม่มีการใช้ external LLM-as-judge แทนผู้ประเมิน |

MCP SDK ที่มีหลักฐานการตรวจ runtime ตอน deployment คือ **1.30.0** ส่วน SDK/protocol version ไม่เท่ากับเวอร์ชัน TShark

Final deployed `server.py` SHA-256 ตาม deployment record:

```text
51e8981556a8ab6656d89e6f2220081a93243b8de65ec81ecab0b6ceb3b1b62c
```

Image digest ตาม deployment record:

```text
sha256:fd12ae9587d42a3b49623e1749d57f14149ae41798c9994a8b7903a22614e58b
```

ข้อมูลเวอร์ชัน/source digest ข้างต้นอ้างบันทึกวันที่นำเข้า ไม่ใช่ผลตรวจ image ปัจจุบันใหม่ในรายงานนี้

## 6. ทะเบียนการตรวจวิเคราะห์ประกอบ CoC

ส่วนนี้ระบุว่ามีการตรวจอะไรและอ้าง packet ใด ไม่ใช้แทนรายงานผลสืบสวนฉบับเต็ม การแสดงผลจาก `hdfs_pcap_packets` จำกัดจำนวนตัวอย่างและ payload ต่อ packet; `complete_scan=true` หมายถึง scan ทั้งไฟล์เพื่อนับผลของ filter ไม่ได้หมายความว่าผู้วิเคราะห์อ่าน payload ทุก packet ครบ

| ประเด็นที่ตรวจ | MCP tool / ตัวอย่าง filter ที่ใช้จริง | Packet references |
|---|---|---|
| ต้นทางการเชื่อม SMB | `hdfs_pcap_packets`: `tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.dstport == 445` | 123, 38506, 38528, 39105, 39693 |
| ชื่อเป้าหมายแรก/ที่สอง | `hdfs_pcap_packets`: NTLM type 2 ในช่วง frame ที่กำหนด | 131, 38514, 38534 |
| บัญชีเป้าหมายแรกและผลตอบกลับ | `hdfs_pcap_packets`: `ntlmssp.auth.username == "ssales"`; ตรวจ status ของ 133 | 132–133 |
| ชื่อ executable | `hdfs_pcap_packets`: `smb2.filename == "PSEXESVC.exe" && frame.number < 331` | 144–145 |
| Share และการเขียนไฟล์ | `hdfs_pcap_packets`: `smb2.cmd == 3`; `smb2.cmd == 9 && frame.number < 331` | 138–139, 144, 240, 248, 318, 319, 322 |
| IPC และ named pipes | `hdfs_pcap_packets`: `smb2.filename contains "PSEXESVC"`; ตรวจ response status | 134–135, 371–372, 499–500, 505–506, 511–512 |

จากผลตรวจได้คำตอบสำหรับ lab: `10.0.0.130`, `Sales-PC`, `ssales` สำหรับ session แรก, `PSEXESVC.exe`, `ADMIN$`, `IPC$`, `Marketing-PC` ตามลำดับ ค่าดังกล่าวไม่ใช่หลักฐานว่า initial compromise ก่อน capture เกิดขึ้นอย่างไร และไม่ควรอนุมานว่า Sales-PC เป็นผู้เริ่ม pivot ไป Marketing-PC เพราะ SYN ที่อ้างเป็น `10.0.0.130 → 10.0.0.131`

Packet time ที่พบเป็นวันที่ **11 ตุลาคม 2023 UTC**; ไม่ใช้เป็นวันรับไฟล์ นำเข้า HDFS หรือวันที่วิเคราะห์ในเดือนกันยายน 2026

[R8] เป็น index อนุพันธ์ที่ตัด payload ออก โดยบันทึก SHA-256/ขนาด/path ของ raw MCP-result JSONL ที่มีอยู่บน Mac และ packet references ที่คืนมา เก็บ raw results เฉพาะ local temporary paths ไม่เผยแพร่ payload/ข้อมูลยืนยันตัวตนลง repository; ยังไม่มีหลักฐานว่า raw result files เหล่านี้อยู่ใน immutable archive

## 7. ช่องว่างและข้อจำกัดของ chain of custody

1. **ก่อนรับไฟล์:** ไม่ทราบผู้จับ traffic, อุปกรณ์/จุด capture, acquisition procedure, เครื่องมือ/เวอร์ชันที่สร้างไฟล์, original hash, วันเวลาส่งมอบครั้งแรก และประวัติการคัดลอก/แก้ไขก่อน path ที่ผู้ใช้ให้
2. **ผู้ดูแลและการลงนาม:** ไม่มีผู้เก็บต้นฉบับ/ผู้ดูแลหลักฐานที่เป็นบุคคลระบุชื่อและลงนาม; account/service identity และบทสนทนาไม่ใช่ลายมือชื่อส่งมอบ
3. **ประวัติการเข้าถึง:** ใช้ MCP endpoint ที่ client ทดสอบเข้าถึงได้โดยไม่ส่ง token แยกผู้เรียน ไม่มี comprehensive access log ที่ตรวจระบุตัวบุคคลผู้เข้าถึงทุกครั้ง จึงไม่รับรอง exclusive custody หรือไม่มีบุคคลอื่นเข้าถึง
4. **การป้องกันแก้ไข:** HDFS permissions ที่ตรวจเป็น 0444/0555 และ original imports mount เป็น read-only ตามบันทึก แต่ไม่ใช่ WORM storage, physical evidence seal หรือขอบเขตความปลอดภัยต่อ privileged administrator / simple-auth impersonation ช่วงหลัง import ก่อนเปลี่ยนสิทธิ์ canonical file เคยเป็น spark-owned 0644
5. **เวลา:** timestamp ของบางกิจกรรมเป็นเวลาเขียนบันทึกย้อนหลัง; raw results การวิเคราะห์ไม่มีเวลาการเรียก tool; ไม่มี clock-synchronization evidence ไม่แทนที่ข้อมูลเหล่านี้ด้วย filesystem mtime หรือ packet timestamps
6. **ขอบเขตความตรงกัน:** hash ตรงกันระหว่างจุดตรวจ ไม่พิสูจน์ว่าไฟล์ไม่เคยถูกเปลี่ยนแล้วเปลี่ยนกลับระหว่างจุดตรวจ และไม่ยืนยันความแท้จริงของเนื้อหา capture ตั้งแต่ต้นทาง
7. **สำเนาชั่วคราวและผลวิเคราะห์:** มี staging/test copies และ temporary examination copies ตาม workflow ที่บันทึก ผลทดสอบยืนยัน cleanup บางจุด แต่ไม่มีทะเบียน temporary file ทุกชิ้นแบบครบถ้วน ไม่มี signed disposal certificate
8. **การเปลี่ยนเครื่องมือ:** มีการ rebuild/recreate MCP สองครั้งระหว่างงานและแก้ HTTP body limit; เก็บ hashes/ผลทดสอบไว้ แต่ไม่ได้ตรวจสอบ chain ของ dependency binaries ทุกตัวหรือรับรอง forensic validation ของเครื่องมือทั้งชุด

ข้อมูลที่ควรเติมเพื่อขยายรายงาน: ชื่อและลายมือชื่อผู้ส่ง/ผู้รับ, เลขคดี, acquisition log และ original hash จากผู้เก็บจริง, records ของการส่งมอบก่อน Mac, รายการผู้เข้าถึง/สิทธิ์, เวลาที่ตรวจสอบย้อนกลับได้ และ retention/disposal policy ห้ามเติมข้อมูลเหล่านี้จากการคาดเดา

## 8. แบบรับรองและรับมอบ — ยังไม่ได้ลงนาม

| บทบาท | ชื่อ–สกุล / หน่วยงาน | วันเวลาและเขตเวลา | ลายมือชื่อ / วิธีรับรอง |
|---|---|---|---|
| ผู้เก็บหลักฐานต้นฉบับ | ยังไม่ได้รับข้อมูล | ยังไม่ได้รับข้อมูล | ยังไม่ได้ลงนาม |
| ผู้ส่งไฟล์ที่ระบุบน Mac | ยังไม่ได้รับข้อมูล | ยังไม่ได้รับข้อมูล | ยังไม่ได้ลงนาม |
| ผู้รับและผู้ดูแลหลักฐานที่เป็นบุคคล | ยังไม่ได้รับข้อมูล | ยังไม่ได้รับข้อมูล | ยังไม่ได้ลงนาม |
| ผู้ตรวจทานรายงาน | ยังไม่ได้รับข้อมูล | ยังไม่ได้รับข้อมูล | ยังไม่ได้ลงนาม |

การเติมแบบรับรองต้องอ้างเหตุการณ์และตัวบุคคลจริง ไม่ลงนามย้อนหลังแทนการส่งมอบที่ไม่มีหลักฐาน

## 9. เอกสารและผลตรวจประกอบ

- **R1:** [Activity record การนำเข้าและเปลี่ยน MCP](../../cloud-activities/2026-09-10-002-psexec-import-and-binary-mcp.md)
- **R2:** [ผลนำเข้าที่ติดสิทธิ์ HDFS](../../cloud-activities/evidence/2026-09-10-psexec-import-permission-failure.json)
- **R3:** [ผล native MCP import และตรวจ integrity](../../cloud-activities/evidence/2026-09-10-psexec-import.json)
- **R4:** [ผลทดสอบครั้งที่เกิด ReadError/HTTP 413](../../cloud-activities/evidence/2026-09-10-native-binary-upload-readerror.json)
- **R5:** [ผล binary upload/replay/negative tests และ cleanup](../../cloud-activities/evidence/2026-09-10-native-binary-upload-verification.json)
- **R6:** [ผล client replay หลังตั้ง read-only](../../cloud-activities/evidence/2026-09-10-binary-upload-client-replay.json)
- **R7:** [Source delta, client, verifier และ provenance](../../cloud-activities/changes/2026-09-10-binary-upload/README.md)
- **R8:** [Index ของผล MCP วิเคราะห์ 7 ข้อที่ตัด payload ออก](support/analysis-record-index.json)
- **R9:** [ผล local/HDFS integrity ณ เวลาจัดทำรายงาน](support/integrity-at-report.json)
- **R10:** [SHA-256 manifest ของรายงานและไฟล์อ้างอิง](SHA256SUMS) — manifest สร้างใหม่สำหรับชุดรายงานนี้ ไม่ใช่ digital signature หรือ timestamp authority

หลักฐานและโค้ดเดิมที่อ้างอยู่ใน destination repository commit `e61854d` บน branch `codex/nf01-binary-upload-20260910` ณ การเริ่มงานรายงานนี้ [Draft PR #1](https://github.com/aekanun2020/2026-Network-Forensics/pull/1) เป็นที่เสนอชุดบันทึกให้ตรวจทาน การมีไฟล์บน Git ไม่ได้แทนการรับรองตัวบุคคลหรือหลักประกันว่า history เปลี่ยนไม่ได้

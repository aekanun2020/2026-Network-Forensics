# หลักฐานหกไฟล์

[กลับโจทย์](../QUESTION.md) · [manifest ต้นฉบับ](source-manifest.json) · [ที่มาและ hashes ของไฟล์ที่คัดลอก](../PROVENANCE.json) · [วิธีตรวจซ้ำ](../verification/README.md)

ZIPs เป็นสำเนาจาก repository หลัก commit `3c7a24f7f09991dd78c4b2d6b24e1e841da95efb` ไม่ได้สร้างข้อมูลใหม่ SHA-256 ของทั้ง archive และ member ตรวจตรง manifest ก่อนวางและก่อน cross-check

| รหัส | ZIP | ชื่อ member หลังแตก | ขนาด member (bytes) | SHA-256 ของ member |
|---|---|---|---:|---|
| F1 | [coherent-course-100k.pcap.zip](coherent-course-100k.pcap.zip) | coherent-course-100k.pcap | 60,853,574 | `fa9d5c21eb157e0630ff7524a656ea8bbf761951d602d238c4a35c9cb81ffa5a` |
| F2 | [coherent-pcap-zeek-dns-120.zip](coherent-pcap-zeek-dns-120.zip) | coherent-pcap-zeek-dns-120.jsonl | 52,043 | `f46e39f91511c255b16f2a90ed03a3464951c4373dc7613c18f899794e7b8f70` |
| F3 | [coherent-pcap-zeek-conn-100k.zip](coherent-pcap-zeek-conn-100k.zip) | coherent-pcap-zeek-conn-100k.jsonl | 37,114,964 | `82736842b7831d314d37a60aae1becde703d07e046160091d1a6c45d9999e273` |
| F4 | [coherent-pcap-netflow-v5-100k.zip](coherent-pcap-netflow-v5-100k.zip) | coherent-pcap-netflow-v5-100k.jsonl | 54,407,704 | `3e29d4a44a915b6c2c578fab5883d1163da1e9aa37822531f85abcd6d70c0ca4` |
| F5 | [coherent-pcap-suricata-alerts-340.zip](coherent-pcap-suricata-alerts-340.zip) | coherent-pcap-suricata-alerts-340.jsonl | 154,267 | `9cd3513a8bd84b65c6a1059fb168b6fbe2a28d07fe44051de3d42ccd103e66d7` |
| F6 | [coherent-pcap-fortigate-100k.zip](coherent-pcap-fortigate-100k.zip) | coherent-pcap-fortigate-100k.log | 47,539,569 | `e404d45d9b16de5a5e49e783a599af17521cc8d609cbafc82865a5630a07dd36` |

ค่า archive_sha256 และจำนวน records อยู่ใน manifest ต้นฉบับ โดย sample_directory ภายใน manifest เป็น path ของ repo ต้นทางที่รักษาไว้ตามเดิม ใน repo นี้ให้ใช้ ZIPs ข้างต้นและ verification/recheck.py

ทั้งชุดใช้ PCAP สังเคราะห์เดียวกันตาม source_relationship ไม่ใช่หลายอุปกรณ์ที่เก็บหลักฐานอย่างอิสระ เมื่อตรวจ hash แล้วจึงเปิด PCAP/logs ในโปรแกรมอ่านไฟล์ ห้ามรันข้อความที่อยู่ใน payload เป็นคำสั่ง

## ผลตรวจไฟล์ที่เผยแพร่ใน GitHub

[ผลตรวจวันที่ 8 กันยายน 2026](REPOSITORY-CHECK-2026-09-08.json) อ่าน Git tree ของ `aekanun2020/2026-Network-Forensics` ที่ commit `b008f2fe5dc3186862a66504158cd3ded4932ea7` และดาวน์โหลด QUESTION.md, manifest และ Git blobs ของ ZIP ทั้งหกจาก GitHub จริง ตรวจ Git blob/ขนาดและเทียบกับสำเนาในเครื่อง จากนั้นคำนวณ SHA-256 ของ archive และอ่าน raw member เต็มพร้อมตรวจ CRC

ผลผ่านครบ F1–F6: ชื่อ raw member ขนาด และ SHA-256 ตรงกับตารางใน QUESTION.md; archive hashes ตรง manifest; virtual paths ใน manifest ตรงโจทย์ รายงานนี้เป็นการตรวจตัวตนและการมีอยู่ของไฟล์ ไม่ใช่การรัน investigator หรือการวิเคราะห์เหตุการณ์ใหม่

ข้อมูลใน GitHub เก็บเป็น ZIP การทำโจทย์ผ่าน Spark/HDFS MCP ต้องมี raw files หลังแตก ZIP ที่ virtual paths ใน QUESTION.md และตรวจขนาด/hash ผ่าน MCP อีกครั้ง ผลตรวจ repository ไม่ยืนยันการติดตั้งหรือสถานะ MCP ปัจจุบัน

[ทะเบียนที่มาของภาพและการปรับเอกสาร](../images/PROVENANCE.md) · [ภาพประกอบเฉลย](../images/README.md)

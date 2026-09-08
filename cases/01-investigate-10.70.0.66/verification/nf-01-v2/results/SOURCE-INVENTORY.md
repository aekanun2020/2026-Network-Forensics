# Source inventory ที่คำนวณจากไฟล์จริง — NF-01-v2

[คำตอบ cross-check](../../../CROSS-CHECK-NF-01-v2.md) · [paths และค่าที่คำนวณจริง](source-inventory.json) · [receipt](receipt.json)

ตรวจ local ZIP และ raw members โดยไม่ใช้ MCP รหัสด้านล่างเป็นชื่อย่อของ filename ที่ระบุ ไม่ใช้ค้นหา dataset อื่น

| รหัส | ชื่อ raw file | Bytes ที่อ่านได้ | SHA-256 ที่คำนวณได้ | เทียบ manifest |
|---|---|---:|---|---|
| F1 | coherent-course-100k.pcap | 60853574 | fa9d5c21eb157e0630ff7524a656ea8bbf761951d602d238c4a35c9cb81ffa5a | ตรง |
| F2 | coherent-pcap-zeek-dns-120.jsonl | 52043 | f46e39f91511c255b16f2a90ed03a3464951c4373dc7613c18f899794e7b8f70 | ตรง |
| F3 | coherent-pcap-zeek-conn-100k.jsonl | 37114964 | 82736842b7831d314d37a60aae1becde703d07e046160091d1a6c45d9999e273 | ตรง |
| F4 | coherent-pcap-netflow-v5-100k.jsonl | 54407704 | 3e29d4a44a915b6c2c578fab5883d1163da1e9aa37822531f85abcd6d70c0ca4 | ตรง |
| F5 | coherent-pcap-suricata-alerts-340.jsonl | 154267 | 9cd3513a8bd84b65c6a1059fb168b6fbe2a28d07fe44051de3d42ccd103e66d7 | ตรง |
| F6 | coherent-pcap-fortigate-100k.log | 47539569 | e404d45d9b16de5a5e49e783a599af17521cc8d609cbafc82865a5630a07dd36 | ตรง |

raw path ที่อ่านจริงในรอบนี้คือ `/private/tmp/nf01-v2-reference-final-20260908/evidence/` ต่อด้วย filename ในตาราง แต่ละไฟล์ใน source-inventory.json มี archive_path_read และ raw_path_read แบบเต็ม ค่า hdfs_virtual_identity เป็นตำแหน่งอ้างอิงจาก manifest ไม่ได้อ้างว่าอ่านผ่าน HDFS ในรอบนี้

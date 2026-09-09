# หลักฐานสำหรับ NF-02

ใช้ประกอบ [โจทย์ NF-02](QUESTION.md) ไฟล์เหล่านี้เป็น log เพิ่มเติมใน HDFS ไม่ใช่หกไฟล์ของ NF-01 ตรวจ paths และ SHA-256 ให้ตรงก่อนวิเคราะห์

ใช้ virtual paths ด้านล่างกับ HDFS MCP ส่วน Spark ต้องใช้ physical path โดยเติม `/mcp` ข้างหน้า virtual path หรือใช้ HDFS URI ที่ตรวจสอบ endpoint แล้ว ไม่เติม `/mcp` ซ้ำ

**ความพร้อมของ lab:** ตรวจว่าทุกไฟล์อ่านได้ผ่าน MCP ที่ผู้เรียนใช้ หากสภาพแวดล้อมมีเฉพาะหกไฟล์ NF-01 จะยังทำโจทย์นี้ไม่ได้ ห้ามนำไฟล์ NF-01 มาแทน ไฟล์ชุดนี้ตรวจพบใน Docker Desktop local; ยังไม่ได้ยืนยันว่ามีใน VM ทุกกลุ่ม

## G01 — c2-dns-beacon-100k.jsonl

```text
/lab13/runs/lab13-c2-dns-100k-20260819T062916Z/input/c2-dns-beacon-100k.jsonl
```

ขนาด 29142955 bytes · SHA-256:

```text
c78a7adea4d99a7ff53c29ffba1b0e2c76bd877af1c1973e9213414556251ed1
```

## G02 — exfil-netflow-100k.jsonl

```text
/lab13/runs/lab13-exfil-netflow-100k-20260819T080751Z/input/exfil-netflow-100k.jsonl
```

ขนาด 47015400 bytes · SHA-256:

```text
3f4444edc34ed8667d5e6673885dcb3195d02f1e2c841e69620c9fec0af3d107
```

## G03 — fortigate-traffic-100k.log

```text
/lab13/runs/fortigate-100k-20260818t105000z/input/fortigate-traffic-100k.log
```

ขนาด 41491774 bytes · SHA-256:

```text
bf81191aeca301381c9b294f62c59d8f3d55bf1041a5b0757f6fb8f0ba1adea2
```

## G04 — huawei-system-100k.log

```text
/lab13/runs/huawei-system-100k-20260818t130000z/input/huawei-system-100k.log
```

ขนาด 11563018 bytes · SHA-256:

```text
61eb7968790df6ca4b23bb4f1dc73df87a950a936b47c8a29297cc0b1c9f8a78
```

## G05 — lateral-zeek-conn-100k.jsonl

```text
/lab13/runs/lab13-lateral-zeek-100k-20260819T083803Z/input/lateral-zeek-conn-100k.jsonl
```

ขนาด 26859051 bytes · SHA-256:

```text
d17eba2c64cbba5f3b1fb23181b5d2590db89396356132232ceddeea49fd7a84
```

## G06 — netflow-v5-100k.jsonl

```text
/lab13/runs/lab13-netflow-v5-100k-20260819T053459Z/input/netflow-v5-100k.jsonl
```

ขนาด 54301660 bytes · SHA-256:

```text
27da03dde779f06dc77a3934ac420b9c3cb9a72065736b0dd4ae8ae24080cc8c
```

## G07 — panos-traffic-100k.log

```text
/lab13/runs/lab13-repeat2-panos-100k-20260819/input/panos-traffic-100k.log
```

ขนาด 49458688 bytes · SHA-256:

```text
cd97290f779dd8e7396c1f9eec57536dd504f08ff14622ba66d1ab41dbfb54c3
```

## G08 — suricata-alerts-100k.jsonl

```text
/lab13/runs/lab13-suricata-ids-100k-20260819T055640Z/input/suricata-alerts-100k.jsonl
```

ขนาด 45233445 bytes · SHA-256:

```text
e2a2f8aa9dc3db785a134fec2c83ab7c0109b0f408f2d7da087ba27329eb2aeb
```

## G09 — zeek-conn-100k.log

```text
/lab13/runs/lab13-zeek-conn-100k-20260819T051238Z/input/zeek-conn-100k.log
```

ขนาด 38377577 bytes · SHA-256:

```text
16ac09922705e2466f42249dc8c70edc6c5d786dfdbfa86f3f6d721766c71764
```

## G10 — zeek-dns-100k.log

```text
/lab13/runs/lab13-repeat2-zeek-dns-100k-20260819/input/zeek-dns-100k.log
```

ขนาด 28856794 bytes · SHA-256:

```text
cc7aa098c3e95f17736d930e82b56e610bee7c2cc85c10020fbb5efaa9455f97
```

## G11 — fortigate-traffic-adversarial-100k.log

```text
/lab13/runs/lab13-fortigate-data-adversarial-100k-20260819T013152Z/input/fortigate-traffic-adversarial-100k.log
```

ขนาด 40745888 bytes · SHA-256:

```text
170304f2e2a16f9ccd64b6e3d005ade8376cdbddaa69ae4c481d481042a4b399
```

## ขอบเขตการใช้ข้อมูล

อ่านทุกแถวและรายงานจำนวนที่ parse ได้/ไม่ได้ แยกสำเนาตาม hash และอย่ารวมยอดจากไฟล์ที่อาจมี records ซ้ำกันโดยไม่ตรวจสอบ การ parse ไม่สำเร็จไม่ใช่หลักฐานโดยตัวเองว่าเกิดการโจมตี

ไฟล์มีหลายรูปแบบและอาจไม่มี timezone หรือปีครบทุกแหล่ง ต้องระบุสิ่งที่ยังไม่ทราบ ห้ามใช้ PCAP ของ NF-01 เป็น packet evidence ของ log ชุดใหม่โดยไม่พิสูจน์ความสัมพันธ์ ไม่มีข้อกำหนดว่าต้องยืนยันการโจมตีสำเร็จครบทั้งสามประเภท

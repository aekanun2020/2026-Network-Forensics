# NF-01-v2 — คำตอบอ้างอิงสำหรับ cross-check จากไฟล์โดยตรง

[โจทย์พร้อมชื่อไฟล์เต็ม](QUESTION.md) · [หลักฐาน ZIP หกไฟล์](evidence/README.md) · [วิธีตรวจซ้ำและผลรอบนี้](verification/nf-01-v2/README.md)

ผู้วิเคราะห์และประเมิน: **Codex ในแอป desktop วันที่ 8 กันยายน 2026** วิธีตรวจ: local files + Python standard library + tcpdump; **ไม่เรียก MCP tool และไม่รัน Spark/PySpark** นี่คือคำตอบอ้างอิงของเฟส cross-check ไม่ใช่ผล investigator ผ่าน MCP รุ่นโมเดลย่อยไม่ได้บันทึกจาก session metadata ใน artifacts นี้ จึงไม่ใส่ชื่อรุ่นโดยเดา

ผู้จัดทำเคยเห็นคำตอบก่อนหน้าในบทสนทนา จึงไม่ใช่ blind test แต่ผลวัดที่แนบเกิดจากการอ่าน raw files ใหม่ สคริปต์รอบนี้ไม่อ่านคำตอบอ้างอิง, oracle หรือผลวัดเก่าเป็น input และไม่ได้เป็นผู้ตัดสินความหมายแทน Codex

## 1. ยืนยันหลักฐานก่อนวิเคราะห์

ใช้ [โจทย์ NF-01-v2 ที่ pin commit](https://github.com/aekanun2020/2026-Network-Forensics/blob/9c4b4c4679aab67a69ec992d5573794186d5ad7f/cases/01-investigate-10.70.0.66/QUESTION.md) และ source manifest จาก commit `9c4b4c4679aab67a69ec992d5573794186d5ad7f` ของ repo นี้ ไฟล์หลักฐานถูกตรึงที่ commit `58a7c4c56726b178737e9f019105218c8cbfb2ee` ตามโจทย์ คำนวณ SHA-256 ของ ZIP และ raw member ใหม่ครบหกไฟล์ ผลตรง manifest ทุกไฟล์ ดู [ตารางชื่อไฟล์/ขนาด/hashes ที่วัดจริง](verification/nf-01-v2/results/SOURCE-INVENTORY.md), [paths ที่อ่านจริง](verification/nf-01-v2/results/source-inventory.json) และ [receipt](verification/nf-01-v2/results/receipt.json)

| รหัสในคำตอบ | ชื่อไฟล์ raw | อ่านทั้งไฟล์ | เกี่ยวกับ 10.70.0.66 |
|---|---|---:|---:|
| F1 | coherent-course-100k.pcap | 699,400 packets | 1,255 packets |
| F2 | coherent-pcap-zeek-dns-120.jsonl | 120 records | 120 records |
| F3 | coherent-pcap-zeek-conn-100k.jsonl | 100,000 records | 265 records |
| F4 | coherent-pcap-netflow-v5-100k.jsonl | 100,000 records | 265 records |
| F5 | coherent-pcap-suricata-alerts-340.jsonl | 340 alerts | 340 alerts |
| F6 | coherent-pcap-fortigate-100k.log | 100,000 records | 265 records |

อ่าน log ครบ 300,460 records และอ่าน PCAP ทั้งไฟล์ ไม่ใช้ตัวอย่างเป็นตัวแทนยอดรวม ไม่มี pagination ในการอ่าน local นี้ เลข record คือบรรทัดใน raw file เริ่มจาก 1 และ packet คือเลขจากต้น PCAP ก่อน filter ดู [records ที่เลือกพร้อม _line](verification/nf-01-v2/results/selected-records.json) และ [packet index ทั้ง 1,255 packets](verification/nf-01-v2/results/packets.tsv)

## 2. คู่ติดต่อ ผู้เริ่ม และข้อมูลตอบกลับ

10.70.0.66 มีคู่สื่อสาร **27 IP** รวม **265 conversations = DNS exchanges บน UDP 120 ชุด + TCP conversations 145 ชุด** มี 700 packets ออกจากเป้าหมายและ 555 packets กลับมายังเป้าหมาย รวม 1,255 packets ข้อมูลชุดนี้ไม่พบ conversation ที่เครื่องอื่นเป็น originator มายัง .66 แต่พบ response traffic จริง จึงต้องแยก “ผู้เริ่มติดต่อ” ออกจาก “ทิศทาง packet”

| คู่ติดต่อ | ผู้เริ่ม / พอร์ตและ protocol ที่ตรวจได้ | การตอบกลับ | Raw locators |
|---|---|---|---|
| 10.70.0.53 | .66; UDP/53 และ DNS payload | DNS A response | F2/F3 #1–120; F1 #1–240 |
| 203.0.113.66 | .66; TCP/443 มี HTTP ข้อความล้วน | handshake และ OK 2 bytes ต่อ upload | F3 #121–240; F1 #241–1080 |
| 10.70.1.1 ถึง 10.70.1.25 | .66; TCP/22,445,3389 | handshake และ OK 2 bytes ต่อคู่ | F3 #241–265; F1 #1081–1255 |

F1 แสดง SYN/SYN-ACK/ACK ใน TCP ทั้ง 145 ชุด เช่น #241–243 และ #1081–1083; tuple และทิศทางใน [conversations.tsv](verification/nf-01-v2/results/conversations.tsv) เทียบกับ F3 ได้ ไม่ใช้ป้าย service หรือ state เพียงอย่างเดียวพิสูจน์ application protocol

## 3. ลำดับเวลาและความถี่

เวลาต่อไปนี้เป็น **UTC วันที่ 24 สิงหาคม 2026** การบวก 7 ชั่วโมงใช้เมื่อต้องการเวลาไทย แต่ตัวเลขรายงานนี้คง UTC ทั้งหมด

| กิจกรรมที่สังเกตได้ | จำนวน | ช่วงห่างของเวลาเริ่ม | เริ่มครั้งแรก → เริ่มครั้งสุดท้าย | Packet สุดท้าย | ระยะ first start → last packet |
|---|---:|---|---|---|---|
| DNS queries | 120 | 119 intervals เท่ากับ 60 s | 00:00:00 → 01:59:00 | 01:59:00.001 | 7,140.001 s |
| HTTP uploads | 120 | 119 intervals เท่ากับ 10 s | 02:10:00 → 02:29:50 | 02:29:50.006 | 1,190.006 s |
| ติดต่อเครื่องภายใน | 25 | 24 intervals เท่ากับ 10 s | 02:40:00 → 02:44:00 | 02:44:00.006 | 240.006 s |

ทุกกลุ่มมี population standard deviation ของ start intervals เท่ากับ 0 ในข้อมูลนี้ DNS กับ uploads ไม่ทับช่วงเวลากัน อ้าง F3 #1–120 / #121–240 / #241–265 และ F1 #1–240 / #241–1080 / #1081–1255 ตามลำดับ ผลคำนวณอยู่ใน [metrics.phases](verification/nf-01-v2/results/metrics.json)

F2 #1–120 สอบถาม `c2-course.evidence.example.test` ได้ A=`203.0.113.66`, NOERROR, TTL 60; PCAP query/response แรกอยู่ #1–2 และสุดท้าย #239–240 ยืนยันว่ามี DNS ที่เป็นคาบ แต่ยังไม่ยืนยัน DNS tunneling หรือ C2 commands

F5.ts ตรงกับเวลา packet ตาม pcap_count เช่น F5 #121 อ้าง F1 #246 ที่ 02:10:00.005; ไม่ถือว่าเป็นเวลาที่ระบบประมวลผลแจ้งเตือน ไม่มีหลักฐาน processing timestamp แยกต่างหากใน fields ที่ตรวจ ส่วน F6 date/time ตรงกับ F3.ts ที่แสดงเป็น UTC ใน fixture นี้ ไม่ใช้ข้อนี้อนุมาน timezone ของอุปกรณ์อื่น

## 4. ปริมาณและความหมายของข้อมูล

ตารางนี้นับ **transport payload bytes** จาก PCAP และเทียบ F3.orig_bytes/resp_bytes, F4.bytes และ F6.sentbyte/rcvdbyte ขาออกหมายถึงออกจาก 10.70.0.66 ขากลับหมายถึงมายัง 10.70.0.66

| ปลายทาง | F3/F4/F6 records | Payload ขาออก | Payload ขากลับ | Packets ออก / กลับ |
|---|---|---:|---:|---:|
| DNS 10.70.0.53 | #1–120 | 5,880 | 7,800 | 120 / 120 |
| ภายนอก 203.0.113.66 | #121–240 | **6,010,330** | **240** | 480 / 360 |
| ภายใน 10.70.1.1–25 | #241–265 | 875 | 50 | 100 / 75 |
| รวมทุกคู่ติดต่อของเป้าหมาย | #1–265 | **6,017,085** | **8,090** | **700 / 555** |

6,017,085 จึงเป็นยอดขาออกทุกปลายทาง ไม่ใช่ยอดส่งออกภายนอก F4 ไม่มี reverse row ของเป้าหมาย แต่ F1/F3/F6 แสดงข้อมูลขากลับ จึงไม่ใช้การไม่มี reverse F4 เป็นหลักฐานว่าไม่มี response

ช่วง HTTP uploads มี `POST /upload/0 HTTP/1.0` ถึง `POST /upload/119 HTTP/1.0`, Host=`exfil.evidence.example.test` และ Content-Length=50000 ครบ 120 requests ใช้ source ports 40120–40239 ตรวจ body เต็มทุก request ได้ body 6,000,000 bytes และ request line/headers/ตัวคั่นรวม 10,330 bytes รวม 6,010,330 bytes พอดี

แต่ละ body มีอักขระชนิดเดียวซ้ำ 50,000 bytes วน A–T ตามลำดับ request คำตอบ `OK` รวม 120 × 2 = 240 bytes ไม่ใช่ HTTP status line และไม่พิสูจน์การบันทึกข้อมูลลงดิสก์ F1 #244 เป็น POST แรก #1077 เป็น POST สุดท้าย; replies อยู่ #245 และ #1078 โดยแต่ละชุดถัดไปห่าง 7 packets ดู [http_requests/http_responses](verification/nf-01-v2/results/measurements.json)

ป้าย HTTPS ใน F6 ไม่ตรงกับ HTTP payload ข้อความล้วนที่อ่านได้บน TCP/443 ส่วน F5 #121–240 ระบุ application_protocol=http ยอด payload ไม่ใช่ยอด Network Layer: ช่วงภายนอกมี **IP bytes ขาออก 6,029,530 และขากลับ 14,640** จากผลรวม IP total length ใน F1 ซึ่งตรง F3.orig_ip_bytes/resp_ip_bytes ไม่ใช่ขนาด PCAP หรือ Ethernet wire bytes

## 5. การติดต่อเครื่องภายในและขอบเขตผลสำเร็จ

| พอร์ต TCP | IP ปลายทาง | จำนวน |
|---|---|---:|
| 22 | 10.70.1.1, .4, .7, .10, .13, .16, .19, .22, .25 | 9 |
| 445 | 10.70.1.2, .5, .8, .11, .14, .17, .20, .23 | 8 |
| 3389 | 10.70.1.3, .6, .9, .12, .15, .18, .21, .24 | 8 |

เลขย่อหลัง IP แรกในแต่ละแถวใช้ prefix 10.70.1. เหมือนกัน ทั้ง 25 เครื่องถูกติดต่อเรียง .1 ถึง .25 เครื่องละหนึ่งครั้ง F3/F6 ใช้ source ports 40240–40264 และแสดง conn_state=SF / zeekstate=SF ตามลำดับ

F1 แสดง `LAB13 coherent remote service probe` ยาว 35 bytes และ `OK` 2 bytes ทุกคู่ รวม 875/50 bytes จึงยืนยันถึง handshake และการแลกเปลี่ยนข้อความ probe ได้ ไม่ใช่ข้อมูลแค่ Layer 4 โดยไม่มี payload แต่ยังไม่เห็นหลักฐาน authentication, session ของ SSH/SMB/RDP, file access, command execution หรือการยึดเครื่องสำเร็จ

สำหรับเครื่อง 10.70.1.n เมื่อ n=1..25: F3/F4/F6 record #240+n, payload ขาออก F1 #1084+7(n−1), ขากลับ packet ถัดไป คู่แรก #1084–1085 และคู่สุดท้าย #1252–1253 ดู [lateral_payloads](verification/nf-01-v2/results/measurements.json)

## 6. การเชื่อม records และการนับซ้ำ

| การเชื่อม / เงื่อนไข | Matched และ cardinality | Unmatched และขอบเขต |
|---|---|---|
| F2 → F3: uid, tuple และ ts เท่ากัน | 120 → 120, หนึ่งต่อหนึ่ง; delta 0 | F2 unmatched 0; F3 อีก 145 TCP records ไม่มี DNS record จับคู่ ซึ่งเป็นคนละชนิดกิจกรรม |
| F4 → F3: source/destination IP/port + protocol; abs(delta) ≤ 0.01 s; ตรวจ bytes/packets | 265 → 265, หนึ่งต่อหนึ่ง; observed delta ประมาณ +1 ถึง +6 ms | unmatched ทั้งสองฝั่ง 0 ใน target subset |
| F6 → F3: parentuid=uid และ tuple; ตรวจ bytes สองทิศทางและ printed time | 265 → 265, หนึ่งต่อหนึ่ง; printed date/time ตรง UTC ของ F3 | unmatched 0; ไม่ได้ใช้ time tolerance เพราะจับคู่ UID และตรวจเวลาที่พิมพ์แยก |
| F5 → F3: tuple และ abs(delta) ≤ 0.01 s; → F1: pcap_count, tuple, abs(ts delta) ≤ 1 µs | 340 → 265; F5 #1–120 DNS, #121–240 uploads, #241–340 ภายใน | unmatched 0; delta ต่อ F3 ประมาณ 0–5 ms; เวลา F5 ตรง packet ที่อ้าง |

F5 ภายใน 100 alerts เป็น **4 alerts ต่อ 25 conversations** จึงไม่ใช่ 100 connections รวม F5 ทั้งไฟล์ 340 alerts ครอบคลุม 265 conversations และ 240 conversations แรกมี alert ชุดละหนึ่งรายการ ผลรายละเอียดทุกคู่และข้อขัดกันอยู่ใน [joins/join_errors](verification/nf-01-v2/results/measurements.json) และ [join_cardinality](verification/nf-01-v2/results/metrics.json)

F1 target sessions ใช้ tuple แบบมีทิศทางจาก .66; F3 target UIDs และ tuples ไม่ซ้ำในชุดนี้ จึงจับคู่ได้ 265 ชุด ตรวจเวลาเริ่มด้วย tolerance 1 µs และ bytes/packets/IP bytes สองทิศทาง ไม่พบความขัดกันใน fields ที่ตรวจ ไม่อ้างว่าการตรวจเหล่านี้เท่ากับตรวจทุก field ทุกความหมายแล้ว

source_relationship ใน manifest ระบุ parent PCAP สังเคราะห์ร่วมกัน และ F6 ระบุ simulation=true, evidence_origin=pcap-derived จึงไม่ถือการตรงกันของหก views เป็นพยานอิสระหกแหล่ง

## 7. ตารางข้อสรุปสำหรับใช้ cross-check

รหัส F1–F6 ในตารางผูกกับ filename เต็มในข้อ 1 เลข locator เป็นของ raw file ส่วนคำสั่งทำซ้ำอยู่ใน [วิธีตรวจรอบนี้](verification/nf-01-v2/README.md) ทุกข้อเป็นการวินิจฉัยของ Codex จากผลวัด ไม่ใช่คะแนนที่สคริปต์ตัดสิน

| Claim ID | ข้อสรุป / ผลวัด | สถานะ | Source + locator | Fields/payload และวิธีตรวจ |
|---|---|---|---|---|
| C01 | ชุดข้อมูลตรง identity ตามโจทย์ | ยืนยันได้ | F1–F6 ทั้งไฟล์ | คำนวณ ZIP/member SHA-256 เทียบ manifest; source-inventory.json |
| C02 | 27 peers / 265 conversations / 1,255 packets | ยืนยันได้ | F3 #1–265; F1 #1–1255 | ทั้งสองทิศทาง, distinct tuples/peers; conversations.tsv และ tcpdump |
| C03 | DNS 120 ครั้งทุก 60 s พร้อม A/NOERROR/TTL | ยืนยันได้ | F2 #1–120; F1 #1–240 | query/answers/TTLs, decoded DNS และผลต่างเวลาเริ่ม |
| C04 | Uploads 120 ครั้งทุก 10 s หลังช่วง DNS | ยืนยันได้ | F3 #121–240; F1 #241–1080 | เวลาเริ่ม, POST payload; metrics.phases |
| C05 | ส่งภายนอก 6,010,330 รับ 240 payload bytes | ยืนยันได้ | F1 #241–1080; F3/F4/F6 #121–240 | filter ปลายทาง 203.0.113.66 แยกทิศทาง; IP bytes เป็นอีก counter |
| C06 | เป็น HTTP ข้อความล้วน และอ่าน body ได้ | ยืนยันได้ | F1 #244+7i และ #245+7i, i=0..119 | POST/Host/Content-Length, full bodies, OK; http_requests/responses |
| C07 | Body 6,000,000 + headers 10,330 bytes | ยืนยันได้ | F1 request packets ของ C06 | แยก CRLFCRLF แล้วนับ raw bytes; 120 bodies × 50,000 |
| C08 | 6,017,085 คือยอดส่งทุกปลายทางของ .66 | ยืนยันได้ | F4 #1–265 | 5,880 DNS + 6,010,330 ภายนอก + 875 ภายใน |
| C09 | ภายใน 25 เครื่อง พอร์ต 22/445/3389 = 9/8/8 | ยืนยันได้ | F3 #241–265; F1 #1081–1255 | distinct destinations, ports, start intervals 10 s |
| C10 | ภายในมี probe 35 bytes / OK 2 bytes ทุกคู่ | ยืนยันได้ | F1 #1084+7i / #1085+7i, i=0..24 | payload เต็ม; 875/50 bytes; ตรวจ handshake จาก flags |
| C11 | 340 alerts ไม่ใช่ 340 conversations | ยืนยันได้ | F5 #1–340 → F3 #1–265 | tuple/time/pcap_count; internal 4 alerts ต่อ conversation |
| C12 | F4 ไม่มี reverse row แต่มี response จริง | ยืนยันได้ | F4 ทั้งไฟล์; F1 #245, #1085 และ replies ทุกชุด | target_destination_records=0; F1/F3/F6 มีขากลับ |
| C13 | หลักฐานมี synthetic parent ร่วมกัน | ยืนยันได้ | manifest; F6 #1–100000 | source_relationship และ simulation; ไม่ตีความเป็นอุปกรณ์อิสระ |
| H01 | DNS เป็นคาบอาจเป็น beaconing/C2 | สมมติฐาน | หลักฐาน C03 | ยังไม่มีคำสั่งควบคุมหรือ malware/process ยืนยัน; DNS tunneling ไม่ได้รับการยืนยัน |
| H02 | Uploads อาจเป็นการนำข้อมูลออกโดยมิชอบ | สมมติฐาน | หลักฐาน C04–C07 | ยืนยัน transfer ได้ แต่ไม่มีไฟล์ต้นทาง/ข้อมูลลับ/สิทธิ์การอนุญาต |
| H03 | Internal fan-out อาจเป็นการสำรวจ/เตรียม lateral movement | สมมติฐาน | หลักฐาน C09–C10 | port/probe pattern ไม่พิสูจน์ remote-service authentication หรือ execution |
| U01 | Login, ยึดเครื่อง หรือขโมยไฟล์สำเร็จ | ยังสรุปไม่ได้ | F1/F3/F6 ของ C09–C10 | ต้องมี authentication/session/endpoint/file-access evidence เพิ่ม |
| U02 | เจ้าของปลายทาง ผู้ใช้ กระบวนการ และเวลา processing alert | ยังสรุปไม่ได้ | ขอบเขต fields ของ F1–F6 | ข้อมูลที่มีไม่ระบุตัวตน/กระบวนการหรือ processing timestamp ที่ต้องการ |

## 8. ข้อจำกัดในการใช้คำตอบนี้

ใช้เป็นคำตอบอ้างอิงของ **ไฟล์ที่ hashes ตรงกับ NF-01-v2 เท่านั้น** ผู้ตรวจยังต้องพิจารณา claim ของคำตอบที่จะตรวจเอง ไม่ให้คะแนนเพียงเพราะข้อความคล้ายเฉลย หาก agent ใช้ชุดข้อมูลอื่น หรือไม่มี trace พอพิสูจน์ว่าอ่านไฟล์/คำนวณ hash/รัน Spark จริง ให้แยกข้อจำกัดด้านกระบวนการออกจากข้อถูกผิดของเนื้อหา

ตัวอ่านรองรับ classic little-endian Ethernet/IPv4 PCAP ตามไฟล์นี้ ไม่ใช่ decoder/reassembly ทั่วไป ในรอบนี้อ่านครบและไม่พบ truncated frame, IP fragments หรือ EtherType อื่น HTTP requests ของชุดนี้อยู่ใน packet payload เดียว จึงนับ body เต็มได้ ข้อเท็จจริงนี้ไม่ได้รับรองตัวอ่านกับ capture รูปแบบอื่น

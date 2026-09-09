# โจทย์ NF-02: สืบสวน C2, Exfiltration และ Lateral Movement

ใช้ **Spark ผ่าน MCP** วิเคราะห์หลักฐานทั้ง 6 ไฟล์ต่อไปนี้ โดยสำรวจทุกเครื่องและค้นหาเครื่องที่ควรตรวจสอบเอง

```text
/student/agentic-siem/incident-lab/input/coherent-course-100k.pcap
/student/agentic-siem/incident-lab/input/coherent-pcap-zeek-dns-120.jsonl
/student/agentic-siem/incident-lab/input/coherent-pcap-zeek-conn-100k.jsonl
/student/agentic-siem/incident-lab/input/coherent-pcap-netflow-v5-100k.jsonl
/student/agentic-siem/incident-lab/input/coherent-pcap-suricata-alerts-340.jsonl
/student/agentic-siem/incident-lab/input/coherent-pcap-fortigate-100k.log
```

**คำถาม**

1. **C2:** การติดต่อใดน่าสงสัยว่าเป็นการควบคุมเครื่องจากระยะไกล? เปรียบเทียบความถี่และเนื้อหาการสื่อสารกับ traffic กลุ่มอื่น พร้อมอธิบายเหตุผลที่เลือก
2. **Exfiltration:** พบการส่งข้อมูลออกไปที่ใด ส่งอะไร และปริมาณเท่าใด? ตรวจ payload และเทียบข้อมูลข้าม log โดยไม่นับซ้ำ พร้อมประเมินว่าหลักฐานยืนยันการขโมยข้อมูลได้หรือยัง
3. **Lateral Movement:** เครื่องใดติดต่อกระจายไปยังเครื่องภายในอื่น? หลักฐานยืนยันได้ถึงขั้นเชื่อมต่อ เข้าสู่ระบบ หรือรันคำสั่ง และยังต้องการหลักฐานใดเพิ่มเติม?

**สิ่งที่ต้องส่ง**

- ตารางลำดับเหตุการณ์ ระบุเวลา IP ต้นทาง–ปลายทาง พอร์ต และกิจกรรม
- ข้อสรุปทั้งสามประเด็น พร้อมชื่อไฟล์และเลขบรรทัดหรือเลข packet ที่รองรับ แยกสิ่งที่ยืนยันได้ ข้อสงสัย และสิ่งที่ยังสรุปไม่ได้
- โค้ด Spark, job ID, สถานะงาน และผลลัพธ์ที่รันจริง พร้อมระบุขอบเขตข้อมูลที่อ่านและข้อผิดพลาดที่พบ

ตรวจขนาดและ SHA-256 ของหลักฐานก่อนและหลังวิเคราะห์ ห้ามแก้ไขต้นฉบับหรือใช้เฉลยและผลวิเคราะห์เก่า **ไม่จำเป็นต้องสรุปว่าพบการโจมตีครบทั้งสามประเภท หากหลักฐานไม่เพียงพอ**

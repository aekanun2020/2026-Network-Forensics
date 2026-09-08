import ast
import copy
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import server


class RegistryTests(unittest.TestCase):
    def test_all_published_skills_load(self) -> None:
        loaded = [server._load_skill(path) for path in server._skill_dirs()]
        self.assertGreaterEqual(len(loaded), 3)
        self.assertIn("normalize-security-logs", {skill["name"] for skill in loaded})

    def test_paloalto_fixture_normalizes_expected_fields(self) -> None:
        parser = server._parser_by_id("parse-paloalto-panos-logs", "paloalto-panos-11x-traffic")
        sample = (server.SKILLS_DIR / "parse-paloalto-panos-logs/assets/samples/panos-traffic.log").read_text().strip()
        record = server._parse_record(parser, sample)
        self.assertEqual("10.0.0.10", record["source_ip"])
        self.assertEqual("8.8.8.8", record["destination_ip"])
        self.assertEqual(51514, record["source_port"])
        self.assertEqual(443, record["destination_port"])
        self.assertEqual("0.0.0.0", record["source_translated_ip"])
        self.assertEqual("0.0.0.0", record["destination_translated_ip"])
        self.assertEqual(0, record["source_translated_port"])
        self.assertEqual(0, record["destination_translated_port"])
        self.assertEqual("allow", record["event_action"])
        self.assertEqual("tcp-fin", record["session_end_reason"])
        self.assertEqual("parsed", record["parse_status"])

    def test_paloalto_source_index_7_is_not_rebased(self) -> None:
        parser = server._parser_by_id("parse-paloalto-panos-logs", "paloalto-panos-11x-traffic")
        sample = (server.SKILLS_DIR / "parse-paloalto-panos-logs/assets/samples/panos-traffic.log").read_text().strip()
        start = server.re.search(parser["parse"]["payload_start_pattern"], sample)
        self.assertIsNotNone(start)
        fields = next(server.csv.reader([sample[start.start():]]))
        record = server._parse_record(parser, sample)
        self.assertEqual(0, parser["parse"]["index_base"])
        self.assertEqual(fields[7], record["source_ip"])
        self.assertNotEqual(fields[6], record["source_ip"])

    def test_huawei_fixture_normalizes_expected_fields(self) -> None:
        parser = server._parser_by_id("parse-huawei-security-logs", "huawei-vrp-system")
        sample = (server.SKILLS_DIR / "parse-huawei-security-logs/assets/samples/huawei-system.log").read_text().strip()
        record = server._parse_record(parser, sample)
        self.assertEqual("HUAWEI", record["device_name"])
        self.assertEqual("SEC", record["vendor_fields"]["module"])
        self.assertEqual("LOGIN_FAIL", record["vendor_fields"]["event_id"])
        self.assertEqual("parsed", record["parse_status"])

    def test_trusted_spark_renderer_accepts_huawei_system_parser(self) -> None:
        rendered = server.log_skill_render_spark_job(
            "parse-huawei-security-logs", "huawei-vrp-system"
        )
        validated = server.log_skill_validate_spark_job(
            "parse-huawei-security-logs", "huawei-vrp-system", rendered["code"]
        )
        self.assertEqual("analyze-system-logs-with-spark", rendered["workflow_skill"])
        self.assertTrue(validated["valid"], validated)
        self.assertEqual(rendered["code_sha256"], validated["code_sha256"])

    def test_fortigate_fixture_and_trusted_renderer_are_vendor_neutral(self) -> None:
        parser = server._parser_by_id(
            "parse-fortinet-fortigate-logs",
            "fortinet-fortigate-7x-forward-traffic",
        )
        sample = (
            server.SKILLS_DIR
            / "parse-fortinet-fortigate-logs/assets/samples/fortigate-traffic.log"
        ).read_text(encoding="utf-8").splitlines()[0]
        record = server._parse_record(parser, sample)
        self.assertEqual("10.10.20.11", record["source_ip"])
        self.assertEqual("8.8.8.8", record["destination_ip"])
        self.assertEqual("Allow Web", record["policy_name"])
        self.assertEqual(1200, record["bytes_sent"])
        self.assertEqual(3400, record["bytes_received"])
        self.assertEqual("parsed", record["parse_status"])

    def test_fortigate_invalid_ip_is_rejected_by_registry_and_rendered_job(self) -> None:
        parser = server._parser_by_id(
            "parse-fortinet-fortigate-logs",
            "fortinet-fortigate-7x-forward-traffic",
        )
        sample = (
            server.SKILLS_DIR
            / "parse-fortinet-fortigate-logs/assets/samples/fortigate-traffic.log"
        ).read_text(encoding="utf-8").splitlines()[0]
        invalid = server.re.sub(r" srcip=\S+", " srcip=999.999.999.999", sample, count=1)
        with self.assertRaises(ValueError):
            server._parse_record(parser, invalid)

        rendered = server.log_skill_render_spark_job(
            "parse-fortinet-fortigate-logs",
            "fortinet-fortigate-7x-forward-traffic",
        )["code"]
        self.assertIn("ipaddress.ip_address", rendered)
        self.assertIn("expression = validated_ip(expression)", rendered)

        rendered = server.log_skill_render_spark_job(
            "parse-fortinet-fortigate-logs",
            "fortinet-fortigate-7x-forward-traffic",
        )
        validated = server.log_skill_validate_spark_job(
            "parse-fortinet-fortigate-logs",
            "fortinet-fortigate-7x-forward-traffic",
            rendered["code"],
        )
        self.assertTrue(validated["valid"], validated)
        self.assertTrue(validated["checks"]["parser_format_supported"])

    def test_pcap_sim_fortigate_requires_explicit_simulation_markers(self) -> None:
        parser=server._parser_by_id("parse-fortinet-fortigate-logs","fortinet-fortigate-pcap-sim-7x")
        self.assertEqual("fortigate-pcap-sim",parser["product"])
        sample='date=2026-08-24 time=00:00:00 type="traffic" subtype="forward" simulation="true" evidence_origin="pcap-derived" srcip=10.70.0.66 dstip=10.70.0.53 action="accept"'
        self.assertEqual("parsed",server._parse_record(parser,sample)["parse_status"])
        with self.assertRaises(ValueError):
            server._parse_record(parser,sample.replace(' simulation="true"',''))
        rendered=server.log_skill_render_spark_job("parse-fortinet-fortigate-logs",parser["id"])
        self.assertTrue(server.log_skill_validate_spark_job("parse-fortinet-fortigate-logs",parser["id"],rendered["code"])["valid"])

    def test_zeek_dns_fixture_resolves_and_normalizes_expected_fields(self) -> None:
        parser = server._parser_by_id("parse-zeek-dns-logs", "zeek-dns-json-v1")
        sample = (
            server.SKILLS_DIR
            / "parse-zeek-dns-logs/assets/samples/zeek-dns.log"
        ).read_text(encoding="utf-8").splitlines()[0]

        record = server._parse_record(parser, sample)
        resolved = server.log_skill_resolve(
            sample, vendor="zeek", product="zeek", log_type="dns"
        )

        self.assertEqual("parsed", record["parse_status"])
        self.assertEqual("zeek-dns-json-v1", resolved["selected"]["parser_id"])
        self.assertTrue(resolved["selected"]["parse_success"])

        rendered = server.log_skill_render_spark_job(
            "parse-zeek-dns-logs", "zeek-dns-json-v1"
        )
        validated = server.log_skill_validate_spark_job(
            "parse-zeek-dns-logs", "zeek-dns-json-v1", rendered["code"]
        )
        self.assertEqual("analyze-dns-logs-with-spark", rendered["workflow_skill"])
        self.assertTrue(validated["valid"], validated)

    def test_zeek_connection_fixture_resolves_and_renders_json_traffic(self) -> None:
        parser = server._parser_by_id(
            "parse-zeek-connection-logs", "zeek-conn-json-v1"
        )
        samples = (
            server.SKILLS_DIR
            / "parse-zeek-connection-logs/assets/samples/zeek-conn.log"
        ).read_text(encoding="utf-8").splitlines()

        udp = server._parse_record(parser, samples[0])
        tcp = server._parse_record(parser, samples[1])
        resolved = server.log_skill_resolve(
            samples[0], vendor="zeek", product="zeek", log_type="traffic"
        )

        self.assertEqual("parsed", udp["parse_status"])
        self.assertEqual("10.20.0.10", udp["source_ip"])
        self.assertEqual(46, udp["bytes_sent"])
        self.assertEqual("parsed", tcp["parse_status"])
        self.assertEqual("http", tcp["application"])
        self.assertEqual("zeek-conn-json-v1", resolved["selected"]["parser_id"])

        rendered = server.log_skill_render_spark_job(
            "parse-zeek-connection-logs", "zeek-conn-json-v1"
        )
        validated = server.log_skill_validate_spark_job(
            "parse-zeek-connection-logs", "zeek-conn-json-v1", rendered["code"]
        )
        self.assertEqual("analyze-security-logs-with-spark", rendered["workflow_skill"])
        self.assertTrue(validated["valid"], validated)

    def test_netflow_v5_fixture_resolves_and_renders_json_traffic(self) -> None:
        parser = server._parser_by_id("parse-netflow-v5-logs", "netflow-v5-json-v1")
        samples = (
            server.SKILLS_DIR
            / "parse-netflow-v5-logs/assets/samples/netflow-v5.jsonl"
        ).read_text(encoding="utf-8").splitlines()

        udp = server._parse_record(parser, samples[0])
        tcp = server._parse_record(parser, samples[1])
        resolved = server.log_skill_resolve(
            samples[0], vendor="netflow", product="netflow-v5", log_type="traffic"
        )

        self.assertEqual("parsed", udp["parse_status"])
        self.assertEqual("observed", udp["event_action"])
        self.assertEqual(80, udp["bytes_sent"])
        self.assertEqual("parsed", tcp["parse_status"])
        self.assertEqual("https", tcp["application"])
        self.assertEqual("netflow-v5-json-v1", resolved["selected"]["parser_id"])

        rendered = server.log_skill_render_spark_job(
            "parse-netflow-v5-logs", "netflow-v5-json-v1"
        )
        validated = server.log_skill_validate_spark_job(
            "parse-netflow-v5-logs", "netflow-v5-json-v1", rendered["code"]
        )
        self.assertEqual("analyze-security-logs-with-spark", rendered["workflow_skill"])
        self.assertTrue(validated["valid"], validated)

    def test_suricata_ids_fixture_resolves_and_renders_ids_report(self) -> None:
        parser = server._parser_by_id(
            "parse-suricata-eve-alerts", "suricata-eve-alert-json-v1"
        )
        samples = (
            server.SKILLS_DIR
            / "parse-suricata-eve-alerts/assets/samples/suricata-alert.jsonl"
        ).read_text(encoding="utf-8").splitlines()
        dns = server._parse_record(parser, samples[0])
        resolved = server.log_skill_resolve(
            samples[0], vendor="oisf", product="suricata", log_type="ids"
        )
        self.assertEqual("parsed", dns["parse_status"])
        self.assertEqual(1300001, dns["signature_id"])
        self.assertEqual("suricata-eve-alert-json-v1", resolved["selected"]["parser_id"])

        rendered = server.log_skill_render_spark_job(
            "parse-suricata-eve-alerts", "suricata-eve-alert-json-v1"
        )
        validated = server.log_skill_validate_spark_job(
            "parse-suricata-eve-alerts", "suricata-eve-alert-json-v1", rendered["code"]
        )
        self.assertEqual("analyze-ids-alerts-with-spark", rendered["workflow_skill"])
        self.assertTrue(validated["valid"], validated)

    def test_zeek_c2_dns_fixture_resolves_and_renders_detection_report(self) -> None:
        parser = server._parser_by_id("parse-zeek-c2-dns-logs", "zeek-c2-dns-json-v1")
        sample = (server.SKILLS_DIR / "parse-zeek-c2-dns-logs/assets/samples/zeek-c2-dns.jsonl").read_text().strip()
        record = server._parse_record(parser, sample)
        resolved = server.log_skill_resolve(sample, vendor="zeek", product="zeek", log_type="c2_dns")
        self.assertEqual("parsed", record["parse_status"])
        self.assertEqual("c2-control.example.test", record["dns_query"])
        self.assertEqual("zeek-c2-dns-json-v1", resolved["selected"]["parser_id"])
        rendered = server.log_skill_render_spark_job("parse-zeek-c2-dns-logs", "zeek-c2-dns-json-v1")
        validated = server.log_skill_validate_spark_job("parse-zeek-c2-dns-logs", "zeek-c2-dns-json-v1", rendered["code"])
        self.assertEqual("analyze-c2-dns-with-spark", rendered["workflow_skill"])
        self.assertTrue(validated["valid"], validated)

    def test_c2_report_semantics_reject_allowlisted_detection(self) -> None:
        report = {
            "report_contract_version":"c2-detection-report-v1",
            "parser":{"id":"zeek-c2-dns-json-v1","version":"1.0.0","vendor":"zeek","product":"zeek","log_type":"c2_dns"},
            "detection_profile":{"id":"dns-periodic-beacon-v1","minimum_events":100,"minimum_average_interval_seconds":55.0,"maximum_average_interval_seconds":65.0,"maximum_interval_stddev_seconds":2.0,"allowlisted_queries":["update.vendor.example.test"]},
            "total_records":1000,"parse_quality":{"parsed":1000,"failed":0},
            "event_time_min":"2026-08-20 00:00:00","event_time_max":"2026-08-20 01:59:00",
            "detections":[{"source_ip":"10.50.0.66","query":"c2-control.example.test","event_count":120,"average_interval_seconds":60.0,"interval_stddev_seconds":0.0,"first_seen":"2026-08-20 00:00:00","last_seen":"2026-08-20 01:59:00"}],
            "detection_summary":{"detected_entities":1,"supporting_events":120},
            "benign_control_summary":{"allowlisted_periodic_groups":1,"allowlisted_periodic_events":120},
        }
        valid = server.log_skill_validate_report(report)
        self.assertTrue(valid["valid"], valid)
        bad = copy.deepcopy(report)
        bad["detections"][0]["query"] = "update.vendor.example.test"
        invalid = server.log_skill_validate_report(bad)
        self.assertFalse(invalid["valid"])
        self.assertTrue(any("allowlisted" in item for item in invalid["errors"]))

    def test_exfil_netflow_resolves_renders_and_rejects_allowlisted_detection(self) -> None:
        parser=server._parser_by_id("parse-netflow-v5-exfil-logs","netflow-v5-exfil-json-v1")
        sample=(server.SKILLS_DIR/"parse-netflow-v5-exfil-logs/assets/samples/exfil-netflow.jsonl").read_text().strip(); record=server._parse_record(parser,sample)
        resolved=server.log_skill_resolve(sample,vendor="netflow",product="netflow-v5",log_type="exfil_netflow")
        self.assertEqual("parsed",record["parse_status"]); self.assertEqual(4_000_000,record["bytes_sent"]); self.assertEqual("netflow-v5-exfil-json-v1",resolved["selected"]["parser_id"])
        rendered=server.log_skill_render_spark_job("parse-netflow-v5-exfil-logs","netflow-v5-exfil-json-v1"); validated=server.log_skill_validate_spark_job("parse-netflow-v5-exfil-logs","netflow-v5-exfil-json-v1",rendered["code"])
        self.assertEqual("analyze-exfiltration-netflow-with-spark",rendered["workflow_skill"]); self.assertTrue(validated["valid"],validated)
        report={"report_contract_version":"exfiltration-detection-report-v1","parser":{"id":"netflow-v5-exfil-json-v1","version":"1.0.0","vendor":"netflow","product":"netflow-v5","log_type":"exfil_netflow"},"detection_profile":{"id":"netflow-outbound-volume-v1","internal_ipv4_prefix":"10.60.","minimum_outbound_bytes":500000000,"minimum_outbound_flows":100,"minimum_outbound_inbound_ratio":10.0,"allowlisted_external_ips":["203.0.113.10"]},"total_records":1000,"parse_quality":{"parsed":1000,"failed":0},"event_time_min":"2026-08-21 00:00:00","event_time_max":"2026-08-21 01:00:00","detections":[{"internal_ip":"10.60.0.66","external_ip":"203.0.113.66","outbound_flows":100,"inbound_flows":1,"outbound_bytes":500000000,"inbound_bytes":1000,"outbound_inbound_ratio":500000.0,"first_seen":"2026-08-21 00:00:00","last_seen":"2026-08-21 01:00:00"}],"detection_summary":{"detected_pairs":1,"supporting_outbound_flows":100,"supporting_outbound_bytes":500000000},"exclusion_summary":{"allowlisted_candidate_pairs":1,"allowlisted_outbound_bytes":1000000000,"high_volume_low_ratio_pairs":1}}
        self.assertTrue(server.log_skill_validate_report(report)["valid"])
        bad=copy.deepcopy(report); bad["detections"][0]["external_ip"]="203.0.113.10"; invalid=server.log_skill_validate_report(bad)
        self.assertFalse(invalid["valid"]); self.assertTrue(any("allowlisted" in x for x in invalid["errors"]))

    def test_coherent_course_exfil_parser_uses_versioned_1070_profile(self) -> None:
        parser=server._parser_by_id("parse-netflow-v5-exfil-logs","netflow-v5-course-exfil-json-v1")
        self.assertEqual("netflow-v5-course",parser["product"])
        rendered=server.log_skill_render_spark_job("parse-netflow-v5-exfil-logs",parser["id"])
        self.assertEqual("analyze-exfiltration-netflow-with-spark",rendered["workflow_skill"])
        self.assertIn('"netflow-v5-course":{"id":"course-netflow-outbound-volume-v1"',rendered["code"])
        validated=server.log_skill_validate_spark_job("parse-netflow-v5-exfil-logs",parser["id"],rendered["code"])
        self.assertTrue(validated["valid"],validated)

    def test_pcap_course_exfil_parser_uses_separate_five_mb_profile(self) -> None:
        parser=server._parser_by_id("parse-netflow-v5-exfil-logs","netflow-v5-pcap-course-exfil-json-v1")
        self.assertEqual("netflow-v5-pcap-course",parser["product"])
        rendered=server.log_skill_render_spark_job("parse-netflow-v5-exfil-logs",parser["id"])
        self.assertIn('"minimum_outbound_bytes":5000000',rendered["code"])
        self.assertIn('"pcap-course-netflow-outbound-volume-v1"',rendered["code"])
        self.assertTrue(server.log_skill_validate_spark_job("parse-netflow-v5-exfil-logs",parser["id"],rendered["code"])["valid"])
        report={"report_contract_version":"exfiltration-detection-report-v1","parser":{"id":parser["id"],"version":"1.0.0","vendor":"netflow","product":"netflow-v5-pcap-course","log_type":"exfil_netflow"},"detection_profile":{"id":"pcap-course-netflow-outbound-volume-v1","internal_ipv4_prefix":"10.70.","minimum_outbound_bytes":5000000,"minimum_outbound_flows":100,"minimum_outbound_inbound_ratio":10.0,"allowlisted_external_ips":["203.0.113.10"]},"total_records":100000,"parse_quality":{"parsed":100000,"failed":0},"event_time_min":"2026-08-24 00:00:00","event_time_max":"2026-08-24 04:43:06","detections":[{"internal_ip":"10.70.0.66","external_ip":"203.0.113.66","outbound_flows":120,"inbound_flows":0,"outbound_bytes":6010330,"inbound_bytes":0,"outbound_inbound_ratio":6010330.0,"first_seen":"2026-08-24 02:10:00","last_seen":"2026-08-24 02:29:50"}],"detection_summary":{"detected_pairs":1,"supporting_outbound_flows":120,"supporting_outbound_bytes":6010330},"exclusion_summary":{"allowlisted_candidate_pairs":0,"allowlisted_outbound_bytes":0,"high_volume_low_ratio_pairs":0}}
        self.assertTrue(server.log_skill_validate_report(report)["valid"])
        bad=copy.deepcopy(report); bad["detections"][0]["outbound_bytes"]=4999999; bad["detection_summary"]["supporting_outbound_bytes"]=4999999
        invalid=server.log_skill_validate_report(bad); self.assertFalse(invalid["valid"]); self.assertTrue(any("selected profile threshold" in x for x in invalid["errors"]))

    def test_lateral_zeek_resolves_renders_and_rejects_allowlisted_source(self) -> None:
        parser=server._parser_by_id("parse-zeek-lateral-conn-logs","zeek-lateral-conn-json-v1")
        sample=(server.SKILLS_DIR/"parse-zeek-lateral-conn-logs/assets/samples/lateral-conn.jsonl").read_text().strip(); record=server._parse_record(parser,sample)
        resolved=server.log_skill_resolve(sample,vendor="zeek",product="zeek",log_type="lateral_movement")
        self.assertEqual("parsed",record["parse_status"]); self.assertEqual(445,record["destination_port"]); self.assertEqual("zeek-lateral-conn-json-v1",resolved["selected"]["parser_id"])
        rendered=server.log_skill_render_spark_job("parse-zeek-lateral-conn-logs","zeek-lateral-conn-json-v1"); validated=server.log_skill_validate_spark_job("parse-zeek-lateral-conn-logs","zeek-lateral-conn-json-v1",rendered["code"])
        self.assertEqual("analyze-lateral-movement-with-spark",rendered["workflow_skill"]); self.assertTrue(validated["valid"],validated)
        report={"report_contract_version":"lateral-movement-detection-report-v1","parser":{"id":"zeek-lateral-conn-json-v1","version":"1.0.0","vendor":"zeek","product":"zeek","log_type":"lateral_movement"},"detection_profile":{"id":"internal-remote-service-fanout-v1","internal_ipv4_prefix":"10.70.","remote_service_ports":[22,445,3389],"minimum_distinct_destinations":20,"minimum_successful_connections":20,"maximum_window_seconds":300,"allowlisted_source_ips":["10.70.0.10"]},"total_records":1000,"parse_quality":{"parsed":1000,"failed":0},"event_time_min":"2026-08-22 00:00:00","event_time_max":"2026-08-22 01:00:00","detections":[{"source_ip":"10.70.0.66","distinct_destinations":20,"successful_connections":20,"remote_service_ports":[22,445,3389],"first_seen":"2026-08-22 00:00:00","last_seen":"2026-08-22 00:04:00","window_seconds":240}],"detection_summary":{"detected_sources":1,"supporting_connections":20,"distinct_destinations":20},"exclusion_summary":{"allowlisted_candidate_sources":1,"below_destination_threshold_sources":1,"over_window_sources":1,"repeated_single_destination_sources":1}}
        valid=server.log_skill_validate_report(report); self.assertTrue(valid["valid"],valid); self.assertEqual("lateral-movement-detection-report-v1",valid["contract"])
        bad=copy.deepcopy(report); bad["detections"][0]["source_ip"]="10.70.0.10"; invalid=server.log_skill_validate_report(bad)
        self.assertFalse(invalid["valid"]); self.assertTrue(any("allowlisted" in x for x in invalid["errors"]))

    def test_trusted_spark_renderer_accepts_and_validates_panos_parser(self) -> None:
        rendered = server.log_skill_render_spark_job(
            "parse-paloalto-panos-logs", "paloalto-panos-11x-traffic"
        )
        validated = server.log_skill_validate_spark_job(
            "parse-paloalto-panos-logs",
            "paloalto-panos-11x-traffic",
            rendered["code"],
        )
        self.assertTrue(validated["valid"], validated)
        self.assertTrue(validated["checks"]["parser_index_base_is_zero"])
        self.assertTrue(validated["checks"]["matches_trusted_template"])

    def test_investigation_handoff_renderer_and_adversarial_semantics(self) -> None:
        sample=(server.SKILLS_DIR/"parse-security-investigation-report/assets/samples/security-investigation-report.jsonl").read_text().strip()
        resolved=server.log_skill_resolve(sample,vendor="normalized",product="security-investigation",log_type="investigation_handoff")
        self.assertEqual("security-investigation-report-json-v1",resolved["selected"]["parser_id"])
        rendered=server.log_skill_render_spark_job("parse-security-investigation-report","security-investigation-report-json-v1")
        validated=server.log_skill_validate_spark_job("parse-security-investigation-report","security-investigation-report-json-v1",rendered["code"])
        self.assertEqual("build-security-investigation-handoff-with-spark",rendered["workflow_skill"]); self.assertTrue(validated["valid"],validated)
        roles=["dns_c2","network_exfil","east_west_lateral"]; ids=["dns_c2-000000000000","network_exfil-000000000000","east_west_lateral-000000000000"]
        timeline=[{"sequence":i+1,"role":role,"event_time":f"2026-08-23 00:{i*10:02d}:00","evidence_id":ids[i],"source_contract":"contract-v1","source_name":f"{role}.jsonl","source_sha256":str(i+1)*64} for i,role in enumerate(roles)]
        report={"report_contract_version":"security-investigation-handoff-v1","parser":{"id":"security-investigation-report-json-v1","version":"1.0.0","vendor":"normalized","product":"security-investigation","log_type":"investigation_handoff"},"total_records":1,"parse_quality":{"parsed":1,"failed":0},"handoff_policy":{"id":"investigation-handoff-policy-v1","source_contract":"security-investigation-report-v1","target":"vendor-neutral-siem","timeline_roles":roles},"source_report":{"contract":"security-investigation-report-v1","canonical_sha256":"3240bad94fb8c2b9f7a90e71039b960ab3bb72cf744d68ec902b1fb690e4206a","total_evidence_records":100000},"cases":[{"case_id":"case-3240bad94fb8c2b9-asset-066","asset_id":"asset-066","entity_ip":"10.80.0.66","priority":"high","disposition":"needs-review","verdict":"rule-hit","timeline":timeline,"analyst_actions":["validate asset identity and ownership","review endpoint and identity telemetry","confirm or dismiss the multi-stage rule hit"],"caveat":"Rule hit only; not a confirmed incident or compromise."}],"handoff_summary":{"case_count":1,"timeline_event_count":3,"needs_review_count":1}}
        self.assertTrue(server.log_skill_validate_report(report)["valid"])
        for mutate in (lambda x:x["cases"][0].update(priority="critical"),lambda x:x["cases"][0]["timeline"].reverse(),lambda x:x["cases"][0]["timeline"][0].update(evidence_id="forged"),lambda x:x["cases"][0].update(caveat="Confirmed compromise.")):
            bad=copy.deepcopy(report); mutate(bad); self.assertFalse(server.log_skill_validate_report(bad)["valid"])

    def test_shared_parent_investigation_handoff_v2_and_adversarial_semantics(self) -> None:
        rendered=server.log_skill_render_spark_job("parse-security-investigation-report","coherent-pcap-investigation-report-json-v2");validated=server.log_skill_validate_spark_job("parse-security-investigation-report","coherent-pcap-investigation-report-json-v2",rendered["code"])
        self.assertEqual("build-security-investigation-handoff-with-spark",rendered["workflow_skill"]);self.assertTrue(validated["valid"],validated)
        oracle_path=server.SKILLS_DIR.parent/"sample-data/coherent-pcap-investigation-handoff-v2.oracle.json"
        if oracle_path.exists():
            oracle=json.loads(oracle_path.read_text());self.assertTrue(server.log_skill_validate_report(oracle)["valid"])
            mutations=[]
            bad=copy.deepcopy(oracle);bad["parent_evidence"]["unique_parent_conversations"]=300460;mutations.append(bad)
            bad=copy.deepcopy(oracle);bad["cases"][0]["corroboration"][1]["simulation"]=False;mutations.append(bad)
            bad=copy.deepcopy(oracle);bad["cases"][0]["timeline"].reverse();mutations.append(bad)
            bad=copy.deepcopy(oracle);bad["cases"][0]["caveats"]=["Confirmed incident."]*4;mutations.append(bad)
            for bad in mutations:self.assertFalse(server.log_skill_validate_report(bad)["valid"])

    def test_correlation_evidence_resolves_renders_and_validates_oracle(self) -> None:
        sample = (server.SKILLS_DIR / "parse-security-correlation-evidence/assets/samples/correlation-evidence.jsonl").read_text().strip()
        resolved = server.log_skill_resolve(sample, vendor="normalized", product="security-evidence", log_type="correlation")
        self.assertEqual("security-correlation-evidence-json-v1", resolved["selected"]["parser_id"])
        rendered = server.log_skill_render_spark_job("parse-security-correlation-evidence", "security-correlation-evidence-json-v1")
        validated = server.log_skill_validate_spark_job("parse-security-correlation-evidence", "security-correlation-evidence-json-v1", rendered["code"])
        self.assertEqual("correlate-security-evidence-with-spark", rendered["workflow_skill"])
        self.assertTrue(validated["valid"], validated)
        oracle = json.loads((server.SKILLS_DIR.parent / "sample-data/multisource-correlation-100k.oracle.json").read_text()) if (server.SKILLS_DIR.parent / "sample-data/multisource-correlation-100k.oracle.json").exists() else None
        if oracle is not None:
            checked = server.log_skill_validate_report(oracle)
            self.assertTrue(checked["valid"], checked)

    def test_shared_parent_pcap_correlation_v2_renders_and_rejects_bad_accounting(self) -> None:
        rendered = server.log_skill_render_spark_job(
            "parse-security-correlation-evidence",
            "pcap-shared-parent-correlation-evidence-json-v2",
        )
        validated = server.log_skill_validate_spark_job(
            "parse-security-correlation-evidence",
            "pcap-shared-parent-correlation-evidence-json-v2",
            rendered["code"],
        )
        self.assertEqual("correlate-security-evidence-with-spark", rendered["workflow_skill"])
        self.assertTrue(validated["valid"], validated)
        oracle_path = server.SKILLS_DIR.parent / "sample-data/coherent-pcap-correlation.oracle.json"
        if oracle_path.exists():
            oracle = json.loads(oracle_path.read_text())
            self.assertTrue(server.log_skill_validate_report(oracle)["valid"])
            bad = copy.deepcopy(oracle)
            bad["parent_evidence"]["unique_parent_conversations"] = 300460
            invalid = server.log_skill_validate_report(bad)
            self.assertFalse(invalid["valid"])
            self.assertTrue(any("parent_evidence" in item for item in invalid["errors"]))

    def test_shared_parent_pcap_adversarial_profile_and_oracle(self) -> None:
        rendered=server.log_skill_render_spark_job("parse-security-correlation-evidence","pcap-shared-parent-correlation-adversarial-json-v2")
        checked=server.log_skill_validate_spark_job("parse-security-correlation-evidence","pcap-shared-parent-correlation-adversarial-json-v2",rendered["code"])
        self.assertTrue(checked["valid"],checked)
        self.assertIn("pcap-shared-parent-security-evidence-adversarial",rendered["code"])
        oracle_path=server.SKILLS_DIR.parent/"sample-data/coherent-pcap-correlation-adversarial.oracle.json"
        if oracle_path.exists():
            oracle=json.loads(oracle_path.read_text());valid=server.log_skill_validate_report(oracle)
            self.assertTrue(valid["valid"],valid)
            self.assertEqual(35,oracle["total_evidence_records"])
            self.assertEqual(3,oracle["exclusion_summary"]["parent_binding_failures"])
            bad=copy.deepcopy(oracle);bad["investigation_candidates"].append(copy.deepcopy(bad["investigation_candidates"][0]));bad["correlation_summary"]={"candidate_count":2,"supporting_evidence_count":10}
            self.assertFalse(server.log_skill_validate_report(bad)["valid"])

    def test_wrong_vendor_record_is_rejected(self) -> None:
        parser = server._parser_by_id("parse-paloalto-panos-logs", "paloalto-panos-11x-traffic")
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            server._parse_record(parser, "<189>Aug 13 10:15:20 HUAWEI %%01SEC/4/LOGIN_FAIL(l)[123]:failed")

    def test_path_traversal_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            server._safe_child(server.SKILLS_DIR, "../outside")

    def test_invalid_draft_yaml_returns_validation_error(self) -> None:
        self.assertTrue(server._validate_parser(["not", "a", "mapping"]))

    def test_csv_parser_rejects_nonzero_and_negative_index_domains(self) -> None:
        parser_path = (
            server.SKILLS_DIR
            / "parse-paloalto-panos-logs/assets/parsers/panos-traffic-11x.yaml"
        )
        config = server.yaml.safe_load(parser_path.read_text(encoding="utf-8"))
        config["parse"]["index_base"] = 1
        config["mapping"][-1] = {"field": "invalid", "type": "string"}
        config["detection"]["discriminator"]["field_index"] = -1
        errors = server._validate_parser(config, "parse-paloalto-panos-logs")
        self.assertTrue(any("index_base" in error for error in errors))
        self.assertTrue(any("mapping source -1" in error for error in errors))
        self.assertTrue(any("discriminator.field_index" in error for error in errors))

    def test_draft_round_trip_is_isolated_from_published_skills(self) -> None:
        skill_markdown = """---
name: test-vendor-log
description: Parse a synthetic test vendor log for registry testing.
---

# Test vendor

Use the reviewed deterministic parser.
"""
        parser_yaml = """id: test-vendor-event
version: '0.1.0'
status: draft
skill: test-vendor-log
vendor: test
product: appliance
log_type: event
format: regex_syslog
detection:
  required_tokens: [TEST]
parse:
  pattern: '^(?P<message>TEST.*)$'
mapping:
  message: {field: message, type: string}
defaults:
  vendor: test
  product: appliance
  log_type: event
"""
        original = server.DRAFTS_DIR
        with TemporaryDirectory() as temp_dir:
            server.DRAFTS_DIR = Path(temp_dir).resolve()
            try:
                saved = server.log_skill_save_draft("test-vendor-log", skill_markdown, parser_yaml)
                fetched = server.log_skill_get_draft("test-vendor-log")
                listed = server.log_skill_list_drafts()
            finally:
                server.DRAFTS_DIR = original
        self.assertTrue(saved["saved"])
        self.assertEqual(saved["sha256"], fetched["sha256"])
        self.assertEqual("test-vendor-log", listed["drafts"][0]["name"])
        self.assertFalse((server.SKILLS_DIR / "test-vendor-log").exists())

    def test_parserless_draft_round_trip(self) -> None:
        skill_markdown = """---
name: test-workflow
description: Coordinate a synthetic parserless workflow for testing.
---

# Test workflow

Follow the reviewed workflow without executing bundled resources.
"""
        original = server.DRAFTS_DIR
        with TemporaryDirectory() as temp_dir:
            server.DRAFTS_DIR = Path(temp_dir).resolve()
            try:
                saved = server.log_skill_save_draft("test-workflow", skill_markdown)
                fetched = server.log_skill_get_draft("test-workflow")
                listed = server.log_skill_list_drafts()
            finally:
                server.DRAFTS_DIR = original
        self.assertTrue(saved["saved"])
        self.assertEqual("workflow", saved["kind"])
        self.assertIsNone(fetched["parser_yaml"])
        self.assertEqual("workflow", fetched["kind"])
        self.assertFalse(listed["drafts"][0]["has_parser"])


class WorkflowResourceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.skills_root = Path(self.temp.name, "skills")
        self.skills_root.mkdir()
        self.original_skills = server.SKILLS_DIR
        server.SKILLS_DIR = self.skills_root.resolve()
        self._create_parser_skill()
        self._create_workflow_skill()

    def tearDown(self) -> None:
        server.SKILLS_DIR = self.original_skills
        self.temp.cleanup()

    @staticmethod
    def _write(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def _create_parser_skill(self) -> None:
        root = self.skills_root / "parse-test-logs"
        self._write(
            root / "SKILL.md",
            """---
name: parse-test-logs
description: Parse deterministic synthetic test logs.
---

# Test parser

Use the exact published mapping.
""",
        )
        self._write(
            root / "assets" / "parsers" / "test.yaml",
            """id: test-parser
version: '1.0.0'
status: approved
skill: parse-test-logs
vendor: test
product: appliance
log_type: traffic
format: csv_syslog
detection:
  required_tokens: [TRAFFIC]
  min_fields: 3
parse:
  index_base: 0
  payload_start_pattern: '(?=TRAFFIC,)'
  delimiter: ','
  quotechar: '"'
mapping:
  0: {field: log_type, type: lowercase}
  1: {field: source_ip, type: ip}
  2: {field: destination_ip, type: ip}
  3: {field: event_time, type: timestamp}
  4: {field: event_action, type: lowercase}
defaults:
  vendor: test
  product: appliance
  log_type: traffic
validation:
  required_output: [event_time, source_ip, destination_ip, event_action]
""",
        )

    def _create_workflow_skill(self) -> None:
        root = self.skills_root / server.WORKFLOW_SKILL
        self._write(
            root / "SKILL.md",
            f"""---
name: {server.WORKFLOW_SKILL}
description: Render and validate a deterministic Spark reporting workflow.
---

# Spark workflow

Render the trusted template and validate its report.
""",
        )
        self._write(
            root / server.SPARK_JOB_TEMPLATE,
            """import json
import sys
from pyspark.sql import functions as F

PARSER = json.loads(__PARSER_JSON_LITERAL__)
INPUT_PATH = sys.argv[1]
CURATED_PATH = sys.argv[2]
REPORT_PATH = sys.argv[3]
parsed = F.from_csv("raw", "c0 STRING", {"sep": ",", "quote": '"', "mode": "PERMISSIVE"})
for source in PARSER["mapping"]:
    field = F.col(f"csv.c{int(source)}")
normalized.write.mode("overwrite").parquet(CURATED_PATH)
spark.createDataFrame([]).coalesce(1).write.mode("overwrite").text(REPORT_PATH)
""",
        )
        self._write(
            root / server.SPARK_POLICY_RESOURCE,
            json.dumps({"id": "pyspark-policy-v1"}),
        )
        required = [
            "parser",
            "total_records",
            "parse_quality",
            "event_time_min",
            "event_time_max",
            "bytes_sent",
            "bytes_received",
            "top_actions",
            "top_applications",
            "top_policies",
            "top_source_zones",
            "top_destination_zones",
            "protocols",
            "top_source_talkers",
            "top_destination_talkers",
            "traffic_by_source_zone",
            "traffic_by_destination_zone",
            "traffic_by_application",
            "session_end_reasons",
            "top_source_users",
            "nat",
        ]
        properties = {
            key: {"type": "array"}
            for key in required
            if key.startswith("top_")
            or key.startswith("traffic_")
            or key in {"protocols", "session_end_reasons"}
        }
        properties.update(
            {
                "parser": {"type": "object"},
                "total_records": {"type": "integer", "minimum": 0},
                "parse_quality": {
                    "type": "object",
                    "additionalProperties": {"type": "integer", "minimum": 0},
                },
                "event_time_min": {"type": ["string", "null"]},
                "event_time_max": {"type": ["string", "null"]},
                "bytes_sent": {"type": "integer", "minimum": 0},
                "bytes_received": {"type": "integer", "minimum": 0},
                "nat": {
                    "type": "object",
                    "required": [
                        "nat_sessions",
                        "source_nat_sessions",
                        "destination_nat_sessions",
                        "top_source_translations",
                        "top_destination_translations",
                    ],
                    "properties": {
                        "nat_sessions": {"type": "integer", "minimum": 0},
                        "source_nat_sessions": {"type": "integer", "minimum": 0},
                        "destination_nat_sessions": {"type": "integer", "minimum": 0},
                        "top_source_translations": {"type": "array"},
                        "top_destination_translations": {"type": "array"},
                    },
                },
                "top_source_talkers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["source_ip", "sessions"],
                        "properties": {
                            "source_ip": {"type": "string"},
                            "sessions": {"type": "integer", "minimum": 0},
                        },
                    },
                },
            }
        )
        self._write(
            root / server.REPORT_CONTRACT_RESOURCE,
            json.dumps(
                {
                    "$id": "security-report-v1",
                    "type": "object",
                    "required": required,
                    "properties": properties,
                }
            ),
        )
        self._write(root / "references" / "guide.md", "# Trusted guide\n")

    @staticmethod
    def _valid_report() -> dict[str, object]:
        report: dict[str, object] = {
            "parser": {
                "id": "test-parser",
                "version": "1.0.0",
                "vendor": "test",
                "product": "appliance",
                "log_type": "traffic",
            },
            "total_records": 2,
            "parse_quality": {"parsed": 2},
            "event_time_min": "2026-08-14T00:00:00Z",
            "event_time_max": "2026-08-14T00:01:00Z",
            "bytes_sent": 20,
            "bytes_received": 10,
            "nat": {
                "nat_sessions": 1,
                "source_nat_sessions": 1,
                "destination_nat_sessions": 0,
                "top_source_translations": [
                    {
                        "source_ip": "10.0.0.1",
                        "source_translated_ip": "198.51.100.1",
                        "sessions": 1,
                        "bytes_sent": 10,
                        "bytes_received": 5,
                        "total_bytes": 15,
                    }
                ],
                "top_destination_translations": [],
            },
        }
        for key in (
            "top_actions",
            "top_applications",
            "top_policies",
            "top_source_zones",
            "top_destination_zones",
            "protocols",
            "session_end_reasons",
        ):
            report[key] = [{"value": f"{key}-value", "count": 2}]
        for key, dimension in (
            ("top_source_talkers", "source_ip"),
            ("top_destination_talkers", "destination_ip"),
            ("traffic_by_source_zone", "source_zone"),
            ("traffic_by_destination_zone", "destination_zone"),
            ("traffic_by_application", "application"),
        ):
            report[key] = [
                {
                    dimension: f"{dimension}-value",
                    "sessions": 2,
                    "bytes_sent": 20,
                    "bytes_received": 10,
                    "total_bytes": 30,
                }
            ]
        report["top_source_users"] = []
        return report

    def test_parserless_workflow_lists_gets_and_validates(self) -> None:
        listed = server.log_skill_list()
        workflow = next(
            skill for skill in listed["skills"] if skill["name"] == server.WORKFLOW_SKILL
        )
        fetched = server.log_skill_get(server.WORKFLOW_SKILL)
        validated = server.log_skill_validate(server.WORKFLOW_SKILL)
        self.assertEqual("workflow", workflow["kind"])
        self.assertEqual([], fetched["parsers"])
        self.assertTrue(validated["valid"])
        self.assertEqual(0, validated["parser_count"])

    def test_resource_discovery_and_read_are_inert(self) -> None:
        listed = server.log_skill_list_resources(server.WORKFLOW_SKILL)
        paths = {item["path"] for item in listed["resources"]}
        self.assertIn("references/guide.md", paths)
        resource = server.log_skill_read_resource(
            server.WORKFLOW_SKILL, "references/guide.md"
        )
        self.assertEqual("# Trusted guide\n", resource["content"])
        self.assertEqual("disabled", resource["execution"])

    def test_resource_traversal_extension_and_symlink_escape_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            server.log_skill_read_resource(server.WORKFLOW_SKILL, "references/../SKILL.md")
        disallowed = self.skills_root / server.WORKFLOW_SKILL / "assets" / "payload.bin"
        self._write(disallowed, "not exposed")
        with self.assertRaisesRegex(ValueError, "extension"):
            server.log_skill_read_resource(server.WORKFLOW_SKILL, "assets/payload.bin")
        outside = Path(self.temp.name, "outside.md")
        outside.write_text("outside", encoding="utf-8")
        link = self.skills_root / server.WORKFLOW_SKILL / "references" / "outside.md"
        os.symlink(outside, link)
        with self.assertRaisesRegex(ValueError, "escapes|Symbolic|symbolic"):
            server.log_skill_read_resource(server.WORKFLOW_SKILL, "references/outside.md")

    def test_oversized_resource_is_not_exposed(self) -> None:
        oversized = (
            self.skills_root
            / server.WORKFLOW_SKILL
            / "references"
            / "oversized.txt"
        )
        self._write(oversized, "x" * (server.MAX_RESOURCE_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            server.log_skill_read_resource(
                server.WORKFLOW_SKILL, "references/oversized.txt"
            )
        listed = server.log_skill_list_resources(server.WORKFLOW_SKILL)
        self.assertNotIn(
            "references/oversized.txt",
            {item["path"] for item in listed["resources"]},
        )

    def test_rendered_spark_job_passes_and_known_bad_job_fails(self) -> None:
        rendered = server.log_skill_render_spark_job("parse-test-logs", "test-parser")
        tree = ast.parse(rendered["code"])
        parser_assignment = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "PARSER"
                for target in node.targets
            )
        )
        parser_literal = parser_assignment.value.args[0].value
        self.assertEqual(
            parser_literal,
            json.dumps(
                json.loads(parser_literal),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
        accepted = server.log_skill_validate_spark_job(
            "parse-test-logs", "test-parser", rendered["code"]
        )
        rejected = server.log_skill_validate_spark_job(
            "parse-test-logs", "test-parser", rendered["code"] + "\ngetArguments()\n"
        )
        shifted = server.log_skill_validate_spark_job(
            "parse-test-logs", "test-parser", rendered["code"] + "\n# 7 -> 6\n"
        )
        self.assertTrue(accepted["valid"], accepted)
        self.assertTrue(accepted["checks"]["matches_trusted_template"])
        self.assertFalse(rejected["valid"])
        self.assertTrue(any("getArguments" in error for error in rejected["errors"]))
        self.assertFalse(shifted["valid"])
        self.assertTrue(any("index shift" in error for error in shifted["errors"]))

    def test_renderer_rejects_csv_parser_without_analytical_core_fields(self) -> None:
        parser_path = (
            self.skills_root / "parse-test-logs" / "assets" / "parsers" / "test.yaml"
        )
        parser = server.yaml.safe_load(parser_path.read_text(encoding="utf-8"))
        parser["mapping"].pop(4)
        parser["validation"]["required_output"].remove("event_action")
        parser_path.write_text(
            server.yaml.safe_dump(parser, sort_keys=False), encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "analytical core fields: event_action"):
            server.log_skill_render_spark_job("parse-test-logs", "test-parser")

    def test_renderer_rejects_nonzero_csv_index_base(self) -> None:
        parser_path = (
            self.skills_root / "parse-test-logs" / "assets" / "parsers" / "test.yaml"
        )
        parser = server.yaml.safe_load(parser_path.read_text(encoding="utf-8"))
        parser["parse"]["index_base"] = 1
        parser_path.write_text(
            server.yaml.safe_dump(parser, sort_keys=False), encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "index_base must be integer 0"):
            server.log_skill_render_spark_job("parse-test-logs", "test-parser")

    def test_report_contract_and_semantic_totals(self) -> None:
        accepted = server.log_skill_validate_report(self._valid_report())
        bad_report = self._valid_report()
        bad_report["parse_quality"] = {"parsed": 1}
        rejected = server.log_skill_validate_report(bad_report)
        negative_report = self._valid_report()
        negative_report["parse_quality"] = {"parsed": -1, "failed": 3}
        negative = server.log_skill_validate_report(negative_report)
        malformed_report = self._valid_report()
        malformed_report["top_source_talkers"] = [{"source_ip": "10.0.0.1"}]
        malformed = server.log_skill_validate_report(malformed_report)
        self.assertTrue(accepted["valid"], accepted)
        self.assertFalse(rejected["valid"])
        self.assertTrue(any("sum to total_records" in error for error in rejected["errors"]))
        self.assertFalse(negative["valid"])
        self.assertTrue(
            any(
                "minimum" in error
                or "non-negative" in error
                or "at least" in error
                for error in negative["errors"]
            )
        )
        self.assertFalse(malformed["valid"])
        self.assertTrue(any("sessions" in error for error in malformed["errors"]))

    def test_report_semantics_reject_blank_parser_and_empty_required_ranking(self) -> None:
        blank_parser = copy.deepcopy(self._valid_report())
        blank_parser["parser"]["id"] = "   "
        blank_result = server.log_skill_validate_report(blank_parser)

        empty_ranking = copy.deepcopy(self._valid_report())
        empty_ranking["top_actions"] = []
        empty_result = server.log_skill_validate_report(empty_ranking)

        self.assertFalse(blank_result["valid"])
        self.assertIn("$.parser.id: must be non-blank", blank_result["errors"])
        self.assertFalse(empty_result["valid"])
        self.assertTrue(
            any("top_actions" in error and "cannot be empty" in error for error in empty_result["errors"])
        )

    def test_report_semantics_reject_bad_byte_identity_duplicates_and_ordering(self) -> None:
        bad_total = copy.deepcopy(self._valid_report())
        bad_total["top_source_talkers"][0]["total_bytes"] = 31
        total_result = server.log_skill_validate_report(bad_total)

        duplicate = copy.deepcopy(self._valid_report())
        duplicate["top_actions"].append(copy.deepcopy(duplicate["top_actions"][0]))
        duplicate_result = server.log_skill_validate_report(duplicate)

        unranked = copy.deepcopy(self._valid_report())
        unranked["top_actions"] = [
            {"value": "low", "count": 1},
            {"value": "high", "count": 2},
        ]
        unranked_result = server.log_skill_validate_report(unranked)

        self.assertFalse(total_result["valid"])
        self.assertTrue(
            any("total_bytes" in error and "bytes_sent + bytes_received" in error for error in total_result["errors"])
        )
        self.assertFalse(duplicate_result["valid"])
        self.assertTrue(any("duplicate value" in error for error in duplicate_result["errors"]))
        self.assertFalse(unranked_result["valid"])
        self.assertTrue(any("not ranked by count" in error for error in unranked_result["errors"]))

    def test_report_coverage_allows_unmapped_vendor_dimensions(self) -> None:
        report = self._valid_report()
        report["field_coverage"] = {
            "mapped": ["event_time", "source_ip", "destination_ip", "event_action"]
        }
        for field in (
            "top_applications",
            "top_policies",
            "top_source_zones",
            "top_destination_zones",
            "protocols",
            "session_end_reasons",
            "traffic_by_source_zone",
            "traffic_by_destination_zone",
            "traffic_by_application",
        ):
            report[field] = []
        validated = server.log_skill_validate_report(report)
        self.assertTrue(validated["valid"], validated)

    def test_report_semantics_reject_parse_time_and_nat_invariants(self) -> None:
        bad_status = copy.deepcopy(self._valid_report())
        bad_status["parse_quality"] = {"unknown": 2}
        status_result = server.log_skill_validate_report(bad_status)

        reversed_time = copy.deepcopy(self._valid_report())
        reversed_time["event_time_min"] = "2026-08-14T00:02:00Z"
        time_result = server.log_skill_validate_report(reversed_time)

        placeholder_nat = copy.deepcopy(self._valid_report())
        placeholder_nat["nat"]["top_source_translations"][0][
            "source_translated_ip"
        ] = "0.0.0.0"
        nat_result = server.log_skill_validate_report(placeholder_nat)

        duplicate_nat_pair = copy.deepcopy(self._valid_report())
        duplicate_nat_pair["nat"]["top_source_translations"].append(
            copy.deepcopy(duplicate_nat_pair["nat"]["top_source_translations"][0])
        )
        duplicate_nat_result = server.log_skill_validate_report(duplicate_nat_pair)

        self.assertFalse(status_result["valid"])
        self.assertTrue(any("statuses are limited" in error for error in status_result["errors"]))
        self.assertFalse(time_result["valid"])
        self.assertTrue(any("must not be later" in error for error in time_result["errors"]))
        self.assertFalse(nat_result["valid"])
        self.assertTrue(any("observed translated IP" in error for error in nat_result["errors"]))
        self.assertFalse(duplicate_nat_result["valid"])
        self.assertTrue(any("duplicate" in error for error in duplicate_nat_result["errors"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)

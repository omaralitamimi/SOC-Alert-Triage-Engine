import unittest
from soc_triage.engine import detect, extract_iocs

class TestEngine(unittest.TestCase):
    def test_bruteforce(self):
        events=[{"event_type":"auth_failure","user":"admin","src_ip":"203.0.113.10"} for _ in range(5)]
        self.assertTrue(any(a["rule"]=="brute_force" for a in detect(events)))
    def test_encoded_powershell(self):
        events=[{"event_type":"process_start","command_line":"powershell.exe -EncodedCommand AAAA"}]
        self.assertEqual(detect(events)[0]["mitre"]["id"],"T1059.001")
    def test_ioc_extraction(self):
        events=[{"src_ip":"203.0.113.1","domain":"lab.example","sha256":"a"*64}]
        i=extract_iocs(events)
        self.assertIn("203.0.113.1",i["ips"]); self.assertIn("a"*64,i["hashes"])
if __name__=="__main__": unittest.main()

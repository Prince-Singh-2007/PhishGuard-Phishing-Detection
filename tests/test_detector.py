import unittest
from detector import analyze_email, analyze_url

class DetectorTests(unittest.TestCase):
    def test_urgent_credential_email_scores_above_low(self):
        result = analyze_email("alerts@example.test", "Urgent account suspended",
                               "Verify now and enter your password immediately.")
        self.assertIn(result["risk"], ("Medium", "High"))

    def test_http_url_flagged(self):
        result = analyze_url("http://example.test/login")
        self.assertGreaterEqual(result["score"], 1)

    def test_empty_url_has_guidance(self):
        result = analyze_url("")
        self.assertTrue(result["findings"])

if __name__ == "__main__":
    unittest.main()

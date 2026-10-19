import unittest
from datetime import datetime,timezone
from llm_forensics.case_naming import case_name,device_label
from llm_forensics.report import render_html
from llm_forensics.scanner import scan
import tempfile

class CaseNamingTests(unittest.TestCase):
    def test_safe_name_and_timestamp(self):
        self.assertEqual(case_name('Test Mac',datetime(2026,10,14,1,2,3,tzinfo=timezone.utc)), 'Test-Mac_2026-10-14_01-02-03-000000Z')
        self.assertEqual(device_label('../../'), 'unknown-device')
        self.assertNotIn('/',device_label('a/b'))
    def test_empty_dashboard(self):
        with tempfile.TemporaryDirectory() as d:
            html=render_html(scan(d))
        self.assertIn('Evidence dashboard',html)
        self.assertIn('Candidate artifacts',html)
        self.assertIn('No supported candidate artifacts',html)
        self.assertIn('aria-live="polite"',html)

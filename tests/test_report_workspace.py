import copy
from html.parser import HTMLParser
import unittest
from llm_forensics.report import render_html
from test_refinements import fixture

class Elements(HTMLParser):
    def __init__(self, text):
        super().__init__(); self.ids=[]; self.panels=[]; self.feed(text)
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if 'id' in attrs:self.ids.append(attrs['id'])
        if 'data-panel' in attrs:self.panels.append(attrs['id'])

class WorkspaceTests(unittest.TestCase):
    def test_sections_and_evidence_are_preserved(self):
        report=fixture(); finding=report['findings'][0]
        finding['observations'][0].update(role='user',text='<script>unsafe()</script>')
        finding['recovery']={'text':'historical-only-marker'}
        original=copy.deepcopy(report)
        page=render_html(report); elements=Elements(page)
        self.assertEqual(elements.panels,['overview','conversations','evidence','timeline'])
        self.assertEqual(len(elements.ids),len(set(elements.ids)))
        chat=page.split('<section id="conversations"')[1].split('<section id="evidence"')[0]
        self.assertIn('Source reference',chat)
        self.assertIn('/original/history',chat)
        self.assertNotIn('historical-only-marker',chat)
        self.assertIn('historical-only-marker',page)
        self.assertIn('&lt;script&gt;unsafe()',page)
        self.assertNotIn('<script>unsafe()',page)
        self.assertIn('a'*64,page)
        self.assertEqual(report,original)
    def test_no_messages_does_not_invent_conversation(self):
        page=render_html(fixture())
        self.assertIn('No role-labelled messages were extracted',page)
        self.assertIn('No timeline data was generated',page)
        self.assertIn('controlled',page)

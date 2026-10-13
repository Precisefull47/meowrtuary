import unittest
import tempfile
import json
from pathlib import Path
from llm_forensics.conversations import parse_versioned
from llm_forensics.scanner import scan


class ConversationTests(unittest.TestCase):
    def fixture(self):
        return {'messages': [{'versions': [
            {'role': 'user', 'content': [{'type': 'text', 'text': 'first'}]},
            {'role': 'user', 'content': [{'type': 'text', 'text': 'edited'}]}]},
            {'versions': [{'role': 'assistant', 'steps': [
                {'content': [{'type': 'text', 'text': 'answer one'}]},
                {'content': [{'type': 'text', 'text': 'answer two'}]}]}]}]}

    def test_all_versions_and_steps_with_exact_pointers(self):
        result = parse_versioned(self.fixture())
        self.assertEqual([x['text'] for x in result['observations']], ['first', 'edited', 'answer one', 'answer two'])
        self.assertEqual(result['observations'][1]['version_index'], 1)
        self.assertEqual(result['observations'][3]['record_locator'], '/messages/1/versions/0/steps/1/content/0/text')
        self.assertTrue(all(x['timestamp'] is None for x in result['observations']))

    def test_unsupported_blocks_report_partial(self):
        value = self.fixture()
        value['messages'][0]['versions'][0]['content'].append({'type': 'image', 'path': '/private/image.png'})
        result = parse_versioned(value)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(len(result['unparsed_records']), 1)

    def test_unknown_schema_does_not_claim_support(self):
        self.assertIsNone(parse_versioned({'messages': [{'role': 'user', 'content': 'generic'}]}))
        result = parse_versioned({'messages': [{'versions': [{'role': 'alien'}]}]})
        self.assertEqual(result['status'], 'unsupported_schema')

    def test_scanner_uses_adapter_and_legacy_path(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / '.cache/lm-studio/conversations/test.json'
            p.parent.mkdir(parents=True)
            p.write_text(json.dumps(self.fixture()), encoding='utf-8')
            result = scan(directory)
            f = result['findings'][0]
            self.assertEqual(f['schema_adapter'], 'lmstudio-versioned-blocks-experimental')
            self.assertEqual(len(f['observations']), 4)

    def test_observed_metadata_selection_and_debug_blocks(self):
        fixture=self.fixture()
        fixture['name']='Synthetic title'
        fixture['createdAt']=1790661321800
        fixture['messages'][0]['currentlySelected']=1
        fixture['messages'][0]['versions'][1]['edited']=True
        step=fixture['messages'][1]['versions'][0]['steps'][0]
        step['genInfo']={'identifier':'synthetic-model','indexedModelIdentifier':'lab/model.gguf','stats':{'predictedTokensCount':4}}
        fixture['messages'][1]['versions'][0]['steps'].append({'type':'debugInfoBlock','debugInfo':'synthetic diagnostic'})
        result=parse_versioned(fixture)
        self.assertEqual(result['status'],'parsed')
        self.assertFalse(result['observations'][0]['is_selected_version'])
        self.assertTrue(result['observations'][1]['is_selected_version'])
        self.assertTrue(result['observations'][1]['edited'])
        self.assertEqual(result['observations'][2]['model_name'],'synthetic-model')
        self.assertTrue(all(r['timestamp'] is None for r in result['observations']))
        self.assertEqual(result['conversation_metadata'][-1]['raw_fields']['createdAt'],1790661321800)

    def test_invalid_selection_does_not_infer_active_version(self):
        for selected in (True,-1,99,'0'):
            fixture=self.fixture();fixture['messages'][0]['currentlySelected']=selected
            result=parse_versioned(fixture)
            self.assertNotIn('is_selected_version',result['observations'][0])

    def test_macos_trash_retains_versions_and_context(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'Users/Analyst/.Trash/123.conversation.json';p.parent.mkdir(parents=True)
            p.write_text(json.dumps(self.fixture()),encoding='utf-8')
            finding=scan(directory,source_os='macos')['findings'][0]
            self.assertEqual(len(finding['observations']),4)
            self.assertEqual(finding['discovery_rule'],'lmstudio-macos-trash')
            self.assertIn('not carved',finding['artifact_context'])

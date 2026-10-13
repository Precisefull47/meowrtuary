import unittest
from unittest.mock import patch
from llm_forensics.menu_navigation import screen,choose,read_key


class NavigationTests(unittest.TestCase):
    def test_compact_layout_and_selection(self):
        text=screen(1,width=80,height=24)
        self.assertIn('2. Analyze evidence',text);self.assertIn('Q Quit',text)
        self.assertLessEqual(len(text.splitlines()),24)
        self.assertTrue(all(len(line)<80 for line in text.splitlines()))
        self.assertNotIn('7. Validate',text);self.assertIn('4. Case tools',text);self.assertIn('5. Diagnostics & validation',text)
    def test_small_terminal(self):
        for width in (20,40,60,80):
            text=screen(3,True,width=width,height=24)
            self.assertTrue(all(len(line)<width for line in text.splitlines()))
            self.assertIn('4. Package',text)
    def test_key_sequences(self):
        with patch('llm_forensics.menu_navigation.os.name','posix'),patch('llm_forensics.menu_navigation.os.read',side_effect=[b'\x1b',b'[',b'B']),patch('llm_forensics.menu_navigation.select.select',return_value=([1],[],[])):
            self.assertEqual(read_key(1),'down')
    def test_dumb_terminal_fallback(self):
        with patch.dict('os.environ',{'TERM':'dumb'}),patch('builtins.input',return_value='q'),patch('builtins.print'):
            self.assertEqual(choose(),'0')

    def test_submenu_routes(self):
        for keys,action in [(['4','1'],'4'),(['4','2'],'5'),(['4','3'],'export'),(['4','4'],'6'),(['5','1'],'doctor'),(['5','2'],'7'),(['4','c','3'],'3')]:
            with self.subTest(keys=keys),patch.dict('os.environ',{'TERM':'dumb'}),patch('builtins.input',side_effect=keys),patch('builtins.print'):
                self.assertEqual(choose(),action)

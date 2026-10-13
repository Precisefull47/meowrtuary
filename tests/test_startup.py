import io, unittest
from unittest.mock import patch
from llm_forensics.startup import frame,play

class StartupTests(unittest.TestCase):
    def test_frames(self):
        frames=[frame(i) for i in range(8)]
        self.assertEqual(len(set(frames)),8)
        for text in frames:
            self.assertTrue(text.isascii())
            self.assertEqual(len(text.splitlines()),11)
            self.assertLessEqual(max(map(len,text.splitlines())),40)
    def test_skip(self):
        with patch('llm_forensics.startup.motion_enabled',return_value=False),patch('sys.stdout',new_callable=io.StringIO) as out:
            play();self.assertEqual(out.getvalue(),'')
    def test_interrupt_restores_cursor(self):
        import os
        with patch('llm_forensics.startup.motion_enabled',return_value=True),patch('shutil.get_terminal_size',return_value=os.terminal_size((80,24))),patch('time.sleep',side_effect=KeyboardInterrupt),patch('sys.stdout',new_callable=io.StringIO) as out:
            with self.assertRaises(KeyboardInterrupt):play()
            self.assertTrue(out.getvalue().endswith('\x1b[?25h'))

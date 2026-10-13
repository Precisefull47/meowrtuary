import io, os, unittest
from unittest.mock import patch
from llm_forensics.terminal import motion_enabled, fit_line
from llm_forensics.menu_navigation import startup_graphic, screen

class MotionTests(unittest.TestCase):
    def test_motion_policy(self):
        with patch.dict(os.environ, {'TERM':'xterm'},clear=True), patch('sys.stdout.isatty',return_value=True):
            self.assertTrue(motion_enabled())
            for key in ('LLF_REDUCED_MOTION','LLF_NO_ANIMATION'):
                with patch.dict(os.environ,{key:'1'}):self.assertFalse(motion_enabled())
            with patch.dict(os.environ,{'NO_COLOR':''}):self.assertTrue(motion_enabled())
        with patch('sys.stdout.isatty',return_value=False):self.assertFalse(motion_enabled())
    def test_redirected_logo_absent(self):
        with patch('sys.stdout',new_callable=io.StringIO) as out:startup_graphic()
        self.assertEqual(out.getvalue(),'')
    def test_cell_clipping(self):
        self.assertEqual(fit_line('研究abc',5),'研究a')
        self.assertEqual(fit_line('ab\x1bc',3),'ab ')
    def test_widths(self):
        for width in (8,12,20,40,80,120):
            for page in ('home','cases','diagnostics'):
                self.assertTrue(all(len(line)<width for line in screen(more=page,width=width).splitlines()))

    def test_logo_and_menu_are_one_compact_block(self):
        for width,height in ((80,24),(170,57)):
            lines=screen(width=width,height=height).splitlines()
            logo_end=next(i for i,line in enumerate(lines) if '( o.o )' in line)
            first=next(i for i,line in enumerate(lines) if '1. Scan' in line)
            self.assertEqual(first-logo_end,2)
            self.assertLess(len(lines),22)

    def test_alternate_screen_restored_on_failure(self):
        from llm_forensics import menu
        with patch('sys.stdout',new_callable=io.StringIO) as out, patch.object(out,'isatty',return_value=True), patch('sys.stdin.isatty',return_value=True), patch.dict(os.environ,{'TERM':'xterm'}), patch.object(menu,'_menu',side_effect=RuntimeError('test')):
            with self.assertRaises(RuntimeError):menu.menu()
            self.assertTrue(out.getvalue().startswith('\x1b[?1049h'))
            self.assertTrue(out.getvalue().endswith('\x1b[?1049l'))
            self.assertIn('\x1b[?25h',out.getvalue())

    def test_horizontal_shortcuts(self):
        text=screen(width=80,height=24)
        footer=next(line for line in text.splitlines() if 'Q Quit' in line)
        self.assertIn('Navigate',footer)
        self.assertIn('Enter Select',footer)
        narrow=screen(width=30,height=24)
        self.assertIn('Q Quit',narrow)
        self.assertTrue(all(len(line)<30 for line in narrow.splitlines()))

    def test_brand_to_right_of_cat(self):
        from llm_forensics import __version__
        text=screen(width=80,height=24)
        line=next(line for line in text.splitlines() if '( o.o )' in line)
        self.assertIn('meowrtuary  v'+__version__,line)
        self.assertGreater(line.index('meowrtuary'),line.index('( o.o )')+7)

import contextlib,io,unittest
from unittest.mock import patch
from llm_forensics.menu_navigation import guided_choice

class GuidedRegressionTests(unittest.TestCase):
    def run_keys(self,items,keys,navigation=True):
        out=io.StringIO()
        with contextlib.redirect_stdout(out),patch('llm_forensics.menu_navigation.keys',return_value=contextlib.nullcontext(0)),patch('llm_forensics.menu_navigation.select.select',return_value=([0],[],[])),patch('llm_forensics.menu_navigation.read_key',side_effect=keys):
            result=guided_choice(items,navigation)
        self.assertIn('\033[?25h',out.getvalue())
        return result,out.getvalue()
    def test_invalid_suffix_cannot_activate_prior_choice(self):
        result,text=self.run_keys([('1','First'),('2','Second')],['1','2','enter','c'])
        self.assertEqual(result,'c');self.assertIn('Invalid option.',text)
    def test_confirmation_blank_requires_explicit_choice(self):
        result,text=self.run_keys([('Y','Confirm'),('N','Decline')],['enter','n','enter'])
        self.assertEqual(result,'N');self.assertIn('Choose y or n',text)
    def test_arrow_after_invalid_selects_first(self):
        result,_=self.run_keys([('1','First'),('2','Second')],['9','down','enter'])
        self.assertEqual(result,'1')
    def test_results_blank_returns_without_opening_folder(self):
        result,_=self.run_keys([('F','Open folder'),('B','Main menu')],['enter'],False)
        self.assertEqual(result,'b')

    def test_report_numbers_are_registered_for_keyboard_selection(self):
        import tempfile
        from pathlib import Path
        from llm_forensics import menu
        with tempfile.TemporaryDirectory() as d:
            case=Path(d);(case/'report.html').write_text('synthetic');rows=[]
            with contextlib.redirect_stdout(io.StringIO()),patch.object(menu,'source_path',return_value=case),patch.object(menu,'options',side_effect=lambda items,**kw:rows.extend(items)),patch.object(menu,'ask',side_effect=menu.Cancel):
                with self.assertRaises(menu.Cancel):menu.reports_flow()
            self.assertIn(('1','Open report.html'),rows)
    def test_double_digit_selection_and_scroll_window(self):
        result,text=self.run_keys([(str(i),'Report '+str(i)) for i in range(1,12)],['1','1','enter'])
        self.assertEqual(result,'11');self.assertIn('Choices',text)

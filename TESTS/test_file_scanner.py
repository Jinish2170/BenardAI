import unittest
from file_scanner import extract_text_from_pdf

class TestFileScanner(unittest.TestCase):
    def test_extract_text_from_pdf(self):
        text = extract_text_from_pdf("sample.pdf")
        self.assertIn("Expected Content", text)

if __name__ == "__main__":
    unittest.main()

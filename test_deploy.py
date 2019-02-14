#!/usr/bin/env python3

import unittest

from deploy import main

class ParserTest(unittest.TestCase):
    """Test a couple parameters"""
    def test_no_input(self):
        self.assertRaisesRegex(SystemExit, "2", main, [])

    def test_invalid_ami(self):
        with self.assertRaisesRegex(SystemExit, "3"):
            main(['bad_ami_1','bad_ami_2'])

if __name__ == '__main__':
    unittest.main()

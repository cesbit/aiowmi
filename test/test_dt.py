import os
import sys
import unittest
sys.path.insert(0, os.path.dirname((os.path.dirname(__file__))))
from aiowmi.dtypes.dt import dt_from_str  # nopep8
from aiowmi.tools import dt_fmt  # nopep8


class TestDtFromStr(unittest.TestCase):

    def test_dt_from_str(self):
        dt = dt_from_str('20220207094949.500000+060')
        self.assertEqual(str(dt), '2022-02-07 09:49:49.500000+01:00')
        self.assertEqual(dt_fmt(dt), '2022-02-07 09:49:49+060')

        dt = dt_from_str('19980525133015.0000000-300')
        self.assertEqual(str(dt), '1998-05-25 13:30:15-05:00')
        self.assertEqual(dt_fmt(dt), '1998-05-25 13:30:15-300')

        dt = dt_from_str('19980525183015.0000000+000')
        self.assertEqual(str(dt), '1998-05-25 18:30:15+00:00')
        self.assertEqual(dt_fmt(dt), '1998-05-25 18:30:15+000')

        dt = dt_from_str('19980525******.0000000+000')
        self.assertEqual(str(dt), '1998-05-25 00:00:00+00:00')
        self.assertEqual(dt_fmt(dt), '1998-05-25 00:00:00+000')


if __name__ == "__main__":
    unittest.main()

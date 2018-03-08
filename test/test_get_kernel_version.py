import unittest
from src.kernelpop import *


class TestGetKernelVersion(unittest.TestCase):

	def test_kali_1(self):
		test_uname = "Linux kali 4.13.0-kali1-amd64 #1 SMP Debian 4.13.4-2kali1 (2017-10-16) x86_64 GNU/Linux"
		expected_kernel_versions = (
			{
				"major": "4",
				"minor": "13",
				"release": "0",
				"patch_level": "kali1"

			},
			{
				"major": "4",
				"minor": "13",
				"release": "4",
				"patch_level": "2kali1"

			}
		)
		actual_kernel_versions = get_kernel_version_from_uname(test_uname)
		self.assertEqual(expected_kernel_versions, actual_kernel_versions)

	def test_kali_2(self):
		test_uname = "Linux kali 4.9.0-kali4-amd64 #1 SMP Debian 4.9.25-1kali1 (2017-10-16) x86_64 GNU/Linux"
		expected_kernel_versions = (
			{
				"major": "4",
				"minor": "9",
				"release": "0",
				"patch_level": "kali4"

			},
			{
				"major": "4",
				"minor": "9",
				"release": "25",
				"patch_level": "1kali1"

			}
		)
		actual_kernel_versions = get_kernel_version_from_uname(test_uname)
		self.assertEqual(expected_kernel_versions, actual_kernel_versions)

	def test_diff_unames_1(self):
		test_uname = "Linux amd64 4.14.0-rc7+ #18 SMP PREEMPT Sun Nov 5 05:52:33 MSK 2017 x86_64 GNU/Linux"
		expected_kernel_versions = (
			{
				"major": "4",
				"minor": "14",
				"release": "0",
				"patch_level": "rc7"

			},
			None
		)
		actual_kernel_versions = get_kernel_version_from_uname(test_uname)
		self.assertEqual(expected_kernel_versions, actual_kernel_versions)

	def test_diff_unames_2(self):
		test_uname = "Linux external4 3.14-kali1-amd64 #1 SMP Debian 3.14.5-1kali1 (2014-06-07) x86_64 GNU/Linux"
		expected_kernel_versions = (
			{
				"major": "3",
				"minor": "14",
				"release": "5",
				"patch_level": "1kali1"
			},
			None
		)
		actual_kernel_versions = get_kernel_version_from_uname(test_uname)
		self.assertEqual(expected_kernel_versions, actual_kernel_versions)

	def test_diff_unames_3(self):
		# should raise an error from exit(0) because we didn't parse out a uname....I might reconsider this behavior
		# it could also pad out to a zero i.e. 3.14 -> 3.14.0
		test_uname = "Linux external4 3.14-kali1-amd64 #1 SMP Debian 3.14-1kali1 (2014-06-07) x86_64 GNU/Linux"
		self.assertRaises(SystemExit, get_kernel_version, uname=test_uname)


if __name__ == "__main__":
	unittest.main()

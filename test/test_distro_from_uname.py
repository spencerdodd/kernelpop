import unittest
from constants import *
from src.kernelpop import os_type_from_full_uname, get_kernel_version_from_uname, distro_from_os_info, \
	architecture_from_uname


class TestGetKernelVersion(unittest.TestCase):
	def test_get_os_type_from_uname(self):
		test_uname = "Linux atlantic 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64 GNU/Linux"

		os_type = """
PRETTY_NAME = "Debian GNU/Linux 9 (stretch)"
NAME = "Debian GNU/Linux"
VERSION_ID = "9"
VERSION = "9 (stretch)"
ID = debian
HOME_URL = "https://www.debian.org/"
SUPPORT_URL = "https://www.debian.org/support"
BUG_REPORT_URL = "https://bugs.debian.org/"
		"""
		parsed_type = os_type_from_full_uname(os_type)
		self.assertEqual("linux", parsed_type)

	def test_get_kernel_version_from_uname(self):
		test_uname_v = "# 1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23)"
		expected_kernel_version = {
			"major": 		"4",
			"minor": 		"9",
			"release": 		"65",
			"patch-level":	"3+deb9u1"
		}
		actual_kernel_version = get_kernel_version_from_uname(test_uname_v)
		self.assertEqual(expected_kernel_version, actual_kernel_version)

	def test_get_kernel_version_from_uname_fail(self):
		test_fail_uname_v = "# 1 SMP Debian hahaaa no uname 4 u (2017-12-23)"
		expected_kernel_version = None
		actual_kernel_version = get_kernel_version_from_uname(test_fail_uname_v)
		self.assertEqual(expected_kernel_version, actual_kernel_version)

	def test_recover_kernel_release_from_uname(self):
		test_kernel_release = "4.9.0-4-amd64"
		expected_kernel_version = {
			"major": "4",
			"minor": "9",
			"release": "0",
			"patch-level": "4"
		}
		actual_kernel_version = get_kernel_version_from_uname(test_kernel_release)
		self.assertEqual(expected_kernel_version, actual_kernel_version)


	def test_distro_from_os_info(self):
		os_type = """
PRETTY_NAME = "Debian GNU/Linux 9 (stretch)"
NAME = "Debian GNU/Linux"
VERSION_ID = "9"
VERSION = "9 (stretch)"
ID = debian
HOME_URL = "https://www.debian.org/"
SUPPORT_URL = "https://www.debian.org/support"
BUG_REPORT_URL = "https://bugs.debian.org/"
"""
		actual_distro = DEBIAN_9
		parsed_distro = distro_from_os_info(os_type)
		self.assertEqual(actual_distro, parsed_distro)

	def test_architecture_from_uname(self):
		test_uname = "Linux atlantic 4.9.0-4-amd64 #1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23) x86_64 GNU/Linux"
		actual_arch = architecture_from_uname(test_uname)
		expected_arch = ARCHITECTURE_amd64
		self.assertEqual(expected_arch, actual_arch)
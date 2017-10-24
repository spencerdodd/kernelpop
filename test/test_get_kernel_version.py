import unittest
from src.kernelpop import get_kernel_version
from src.kernelpop import Kernel


class TestGetKernelVersion(unittest.TestCase):

	def test_kernel_parsing(self):
		test_linux_uname = "Linux-4.10.0-37-generic-x86_64-with-Ubuntu-16.04-xenial"
		test_linux_kernel = Kernel(test_linux_uname)
		self.assertEqual(test_linux_kernel.name, "xenial")
		self.assertEqual(test_linux_kernel.type, "linux")
		self.assertEqual(test_linux_kernel.major_version, "4")
		self.assertEqual(test_linux_kernel.minor_version, "10")
		self.assertEqual(test_linux_kernel.release, "37")
		self.assertEqual(test_linux_kernel.architecture, "x86_64")
		self.assertEqual(test_linux_kernel.uname, test_linux_uname)

		test_mac_uname = "Darwin-16.7.0-x86_64-i386-64bit"
		test_mac_kernel = Kernel(test_mac_uname)
		self.assertEqual(test_mac_kernel.name, "Darwin")
		self.assertEqual(test_mac_kernel.type, "mac")
		self.assertEqual(test_mac_kernel.major_version,"16")
		self.assertEqual(test_mac_kernel.minor_version, "7")
		self.assertEqual(test_mac_kernel.release, "0")
		self.assertEqual(test_mac_kernel.architecture, "x86_64")
		self.assertEqual(test_mac_kernel.uname, test_mac_uname)


if __name__ ==  "__main__":
	unittest.main()
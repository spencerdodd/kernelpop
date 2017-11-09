import unittest
from src.kernelpop import get_kernel_version
from src.kernelpop import Kernel


class TestGetKernelVersion(unittest.TestCase):

	def test_kernel_parsing(self):
		test_linux_platform = "Linux-4.10.0-37-generic-x86_64-with-Ubuntu-16.04-xenial"
		test_linux_kernel = Kernel(test_linux_platform)
		self.assertEqual(test_linux_kernel.name, "xenial")
		self.assertEqual(test_linux_kernel.type, "linux")
		self.assertEqual(test_linux_kernel.major_version, 4)
		self.assertEqual(test_linux_kernel.minor_version, 10)
		self.assertEqual(test_linux_kernel.release, 37)
		self.assertEqual(test_linux_kernel.architecture, "x86_64")
		self.assertEqual(test_linux_kernel.uname, test_linux_platform)

		test_mac_platform = "Darwin-16.7.0-x86_64-i686-64bit"
		test_mac_kernel = Kernel(test_mac_platform)
		self.assertEqual(test_mac_kernel.name, "Darwin")
		self.assertEqual(test_mac_kernel.type, "mac")
		self.assertEqual(test_mac_kernel.major_version, 16)
		self.assertEqual(test_mac_kernel.minor_version, 7)
		self.assertEqual(test_mac_kernel.release, 0)
		self.assertEqual(test_mac_kernel.architecture, "x86_64")
		self.assertEqual(test_mac_kernel.uname, test_mac_platform)

	def test_uname_input(self):
		test_linux_platform = "Linux-4.10.0-37-generic-x86_64-with-Ubuntu-16.04-xenial"
		test_mac_platform = "Darwin-16.7.0-x86_64-i686-64bit"
		test_linux_uname = "Linux ubuntuexploit 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 " \
			"UTC 2017 x86_64 x86_64 x86_64 GNU/Linux"
		test_mac_uname = "Darwin coastals-MacBook-Pro.local 16.7.0 Darwin Kernel Version 16.7.0: Thu Jun 15 " \
			"17:36:27 PDT 2017; root:xnu-3789.70.16~2/RELEASE_X86_64 x86_64"
		test_rpi_uname = "Linux-3.16.0-4-686-pae-i686-with-debian-8.9"

		# have to set the unames to None because input for platform and uname kernels is different
		test_linux_platform_kernel = Kernel(test_linux_platform).uname = None
		test_linux_uname_kernel = Kernel(test_linux_uname, uname=True).uname = None
		test_mac_platform_kernel = Kernel(test_mac_platform).uname = None
		test_mac_uname_kernel = Kernel(test_mac_uname, uname=True).uname = None

		self.assertEqual(test_linux_platform_kernel, test_linux_uname_kernel)
		self.assertEqual(test_mac_platform_kernel, test_mac_uname_kernel)

	def test_kali(self):
		test_kali_uname_1 = "Linux kali 4.13.0-kali1-amd64 #1 SMP Debian 4.13.4-2kali1 (2017-10-16) x86_64 GNU/Linux"
		test_kali_uname_2 = "Linux kali 4.9.0-kali4-amd64 #1 SMP Debian 4.9.25-1kali1 (2017-10-16) x86_64 GNU/Linux"
		test_kali_kernel_1 = Kernel(test_kali_uname_1, uname=True)
		test_kali_kernel_2 = Kernel(test_kali_uname_2, uname=True)
		self.assertEqual(test_kali_kernel_1.release, 4)
		self.assertEqual(test_kali_kernel_2.release, 25)

	def test_diff_uname(self):
		test_uname = "Linux amd64 4.14.0-rc7+ #18 SMP PREEMPT Sun Nov 5 05:52:33 MSK 2017 x86_64 GNU/Linux"
		test_uname_kernel = Kernel(test_uname, uname=True)
		self.assertEqual(test_uname_kernel.release, 7)

if __name__ ==  "__main__":
	unittest.main()
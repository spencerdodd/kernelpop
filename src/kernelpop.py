import os
import sys
import platform


class Kernel():
	def __init__(self, kernel_version):
		self.type, self.name, self.major_version, self.minor_version, \
			self.release, self.architecture, self.bitness, self.uname = self.process_kernel_version(kernel_version)

	@staticmethod
	def process_kernel_version(kernel_version):
		if "Darwin" in kernel_version:
			print("Underlying OS identified as an OS X variant")
			k_type = 			"mac"
			k_name = 			kernel_version.split("-")[0]
			k_major = 			kernel_version.split("-")[1].split(".")[0]
			k_minor = 			kernel_version.split("-")[1].split(".")[1]
			k_release = 		kernel_version.split("-")[1].split(".")[2]
			k_architecture = 	'-'.join(kernel_version.split("-")[2:4])
			k_bitness = 		kernel_version.split("-")[4]

			return k_type, k_name, k_major, k_minor, k_release, k_architecture, k_bitness, kernel_version

		# running on linux
		elif "Linux" in kernel_version["normal"]:
			print("Underlying OS identified as a Linux variant")
		# running on windows
		elif "win" in kernel_version["normal"]:
			print("Underlying OS identified as a Windows variant")
		# don't know what we're on
		else:
			print("Could not identify underlying OS")


def get_kernel_version():
	"""
	get_kernel_version()

	Determines the version of the kernel running on the underlying operating system. Uses the 'platform' package to
	ensure cross-compatibility between MacOS (OS X), Windows, and Linux hosts.

	:returns: Kernel object
	"""
	kernel_version = {
		"normal": 	platform.platform(),
		"aliased":	platform.platform(aliased=True),
		"terse":	platform.platform(terse=True)
	}
	return Kernel(kernel_version["normal"])


def find_exploit_locally(kernel_version):
	"""

	:param kernel_version: dictionary of the kernel version returned from `get_kernel_version()`
	:returns: array of unique exploit identifiers possible for this kernel
	"""
	pass


def find_exploit_remotely(kernel_version):
	"""

	:param kernel_version: dictionary of the kernel version returned from `get_kernel_version()`
	:return: array of unique exploit identifiers possible for this kernel
	"""


def kernelpop(exploit_db=None):
	"""
	kernelpop()

	Runs the show
	:return:
	"""
	kernel = get_kernel_version()






if __name__ == "__main__":
	kernelpop()

import os
import sys
import platform


def get_kernel_version():
	"""
	get_kernel_version()

	Determines the version of the kernel running on the underlying operating system. Uses the 'platform' package to
	ensure cross-compatibility between MacOS (OS X), Windows, and Linux hosts.

	:returns: dictionary of the kernel version in decreasing verbosity (normal->aliased->terse)
	"""
	kernel_version = {
		"normal": 	platform.platform(),
		"aliased":	platform.platform(aliased=True),
		"terse":	platform.platform(terse=True)
	}

	return kernel_version


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
	get_kernel_version()


if __name__ == "__main__":
	kernelpop()

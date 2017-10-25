import os
import sys
import platform
from pydoc import locate
from constants import LINUX_EXPLOIT_PATH, HIGH_RELIABILITY, MEDIUM_RELIABILITY, LOW_RELIABILITY, HEADER

class Kernel:
	def __init__(self, kernel_version, uname=False):
		self.type, self.distro, self.name, self.major_version, self.minor_version, \
			self.release, self.architecture, self.uname = self.process_kernel_version(kernel_version, uname=uname)

		self.alert_kernel_discovery()

	def parse_distro(self, kernel_version):
		"""
		grabs the distro name if it can from a distribution string (platform.platform() call result)

		:param kernel_version: String from platform.platform()
		:return: String of distro name if it exists
		"""
		if "linux" in kernel_version.lower():
			distros = ["ubuntu", "debian", "enterprise"]
			for distro in distros:
				if distro in kernel_version.lower():
					return distro

		return "unknown"

	def process_kernel_version(self, kernel_version, uname=False):
		# running on mac
		# Darwin-16.7.0-x86_64-i386-64bit
		if "Darwin" in kernel_version:
			print("[+] underlying os identified as a mac variant")
			if uname:
				k_type = 			"mac"
				k_distro = 			self.parse_distro(kernel_version)
				k_name = 			kernel_version.split(" ")[0]
				k_major =		 	kernel_version.split(" ")[2].split(".")[0]
				k_minor = 			kernel_version.split(" ")[2].split(".")[1]
				k_release = 		kernel_version.split(" ")[2].split(".")[2]
				k_architecture = 	kernel_version.split(" ")[-1]
				return k_type, k_distro, k_name, k_major, k_minor, k_release, k_architecture, kernel_version
			else:
				k_type = 			"mac"
				k_distro = 			self.parse_distro(kernel_version)
				k_name = 			kernel_version.split("-")[0]
				k_major = 			kernel_version.split("-")[1].split(".")[0]
				k_minor = 			kernel_version.split("-")[1].split(".")[1]
				k_release = 		kernel_version.split("-")[1].split(".")[2]
				k_architecture = 	kernel_version.split("-")[2]

				return k_type, k_distro, k_name, k_major, k_minor, k_release, k_architecture, kernel_version

		# running on linux
		# Linux-4.10.0-37-generic-x86_64-with-Ubuntu-16.04-xenial
		elif "Linux" in kernel_version:
			print("[+] underlying os identified as a linux variant")
			if uname:
				k_type = 			"linux"
				k_distro = 			self.parse_distro(kernel_version)
				k_name = 			kernel_version.split(" ")[0]
				k_major = 			kernel_version.split(" ")[2].split(".")[0]
				k_minor = 			kernel_version.split(" ")[2].split(".")[1]
				k_release = 		kernel_version.split(" ")[2].split("-")[1]
				k_architecture = 	kernel_version.split(" ")[-2]
				return k_type, k_distro, k_name, k_major, k_minor, k_release, k_architecture, kernel_version
			else:
				k_type = 			"linux"
				k_distro = 			self.parse_distro(kernel_version)
				k_name = 			kernel_version.split("-")[-1]
				k_major = 			kernel_version.split("-")[1].split(".")[0]
				k_minor = 			kernel_version.split("-")[1].split(".")[1]
				k_release = 		kernel_version.split("-")[2]
				k_architecture = 	kernel_version.split("-")[4]
				return k_type, k_distro, k_name, k_major, k_minor, k_release, k_architecture, kernel_version

		# running on windows
		elif "win" in kernel_version:
			print("[+] underlying os identified as a windows variant")
		# don't know what we're on
		else:
			print("[-] could not identify underlying os")
			exit(1)

	def alert_kernel_discovery(self):
		if self.type == "linux":
			print("[+] kernel {} identified as:\n\ttype:\t\t\t{}\n\tdistro:\t\t\t{}\n\tversion:\t\t{}-{}" \
				"\n\tarchitecture:\t\t{}".format(
				self.uname, self.type, self.distro, ".".join([self.major_version, self.minor_version]), self.release,
				self.architecture))
		elif self.type == "mac":
			print("[+] kernel {} identified as:\n\ttype:\t\t\t{}\n\tversion:\t\t{}\n\tarchitecture:\t\t{}".format(
				self.uname, self.type, ".".join([self.major_version, self.minor_version, self.release]),
				self.architecture))
		elif self.type == "windows":
			pass
		else:
			exit(1)

def get_kernel_version(uname=None):
	"""
	get_kernel_version()

	Determines the version of the kernel running on the underlying operating system. Uses the 'platform' package to
	ensure cross-compatibility between MacOS (OS X), Windows, and Linux hosts.

	:returns: Kernel object
	"""
	if not uname:
		kernel_version = {
			"normal": 	platform.platform(),
			"aliased":	platform.platform(aliased=True),
			"terse":	platform.platform(terse=True)
		}

		return Kernel(kernel_version["normal"])
	else:
		return Kernel(uname, uname=True)


def potentially_vulnerable(kernel_version, exploit_module):
	major_v = 	kernel_version.major_version
	minor_v = 	kernel_version.minor_version
	release_v = kernel_version.release

	for vulnerable_version in exploit_module.vulnerable_kernels["confirmed"]:
		if vulnerable_version.split(".")[0] == major_v and vulnerable_version.split(".")[1] == minor_v \
			and vulnerable_version.split(".")[2] == release_v:
			return True

	for vulnerable_version in exploit_module.vulnerable_kernels["potential"]:
		if vulnerable_version.split(".")[0] == major_v and vulnerable_version.split(".")[1] == minor_v \
			and vulnerable_version.split(".")[2] == release_v:
			return True

	if "all" in exploit_module.vulnerable_kernels["potential"]:
		return True

	return False


def find_exploit_locally(kernel_version):
	"""
	find_exploit_locally(Kernel kernel_version)

	Identifies potential exploits for the given kernel by dynamically loading exploit modules from the identified
	operating system's `exploit` dir and checking the kernel vs the list of vulnerable kernels in that exploit.

	:param kernel_version: Kernel() object containing kernel information
	:returns: array of arrays of exploit modules sorted in order of likelihood of success
		i.e. [ [high] [medium] [low] ]
	"""
	potential_exploits = {
		HIGH_RELIABILITY: [],
		MEDIUM_RELIABILITY: [],
		LOW_RELIABILITY: []
	}
	print("[*] matching kernel to known exploits")
	if kernel_version.type == "linux":
		all_exploits = os.listdir(LINUX_EXPLOIT_PATH)
		for exploit_file in all_exploits:
			if exploit_file[-3:] == ".py" and "__init__" not in exploit_file:
				exploit_name = exploit_file.replace(".py", "")
				exploit_module = locate("exploits.linux.{}.{}".format(exploit_name, exploit_name))
				exploit_instance = exploit_module()
				if potentially_vulnerable(kernel_version, exploit_instance):
					print("\t[+] found potential kernel exploit: {}".format(exploit_instance.name))
					potential_exploits[exploit_instance.reliability].append(exploit_instance)
				else:
					del exploit_module

	return potential_exploits


def find_exploit_remotely(kernel_version):
	"""

	:param kernel_version: dictionary of the kernel version returned from `get_kernel_version()`
	:return: array of unique exploit identifiers possible for this kernel
	"""
	pass

def display_identified_exploits(identified_exploits):
	print("[*] identified exploits")
	if len(identified_exploits[HIGH_RELIABILITY]) > 0:
		print("\t[[ high reliability ]]")
		for high_exploit in identified_exploits[HIGH_RELIABILITY]:
			print("\t\t{}\t{}".format(high_exploit.name, high_exploit.brief_desc))
	if len(identified_exploits[MEDIUM_RELIABILITY]) > 0:
		print("\t[[ medium reliability ]]")
		for medium_exploit in identified_exploits[MEDIUM_RELIABILITY]:
			print("\t\t{}\t{}".format(medium_exploit.name, medium_exploit.brief_desc))
	if len(identified_exploits[LOW_RELIABILITY]) > 0:
		print("\t[[ low reliability ]]")
		for low_exploit in identified_exploits[LOW_RELIABILITY]:
			print("\t\t{}\t{}".format(low_exploit.name, low_exploit.brief_desc))
	if len(identified_exploits[HIGH_RELIABILITY]) == 0 and len(identified_exploits[MEDIUM_RELIABILITY]) == 0 \
		and len(identified_exploits[LOW_RELIABILITY]) == 0:
		print("\t[-] no exploits were discovered for this kernel")


def brute_force_exploit(identified_exploits):
	print("[*] attempting brute force of all discovered exploits from most to least probable")
	if len(identified_exploits[HIGH_RELIABILITY]) > 0:
		print("\t[[ high reliability ]]")
		for high_exploit in identified_exploits[HIGH_RELIABILITY]:
			high_exploit.exploit()
	if len(identified_exploits[MEDIUM_RELIABILITY]) > 0:
		print("\t[[ medium reliability ]]")
		for medium_exploit in identified_exploits[MEDIUM_RELIABILITY]:
			medium_exploit.exploit()
	if len(identified_exploits[LOW_RELIABILITY]) > 0:
		print("\t[[ low reliability ]]")
		for low_exploit in identified_exploits[LOW_RELIABILITY]:
			low_exploit.exploit()
	if len(identified_exploits[HIGH_RELIABILITY]) == 0 and len(identified_exploits[MEDIUM_RELIABILITY]) == 0 \
		and len(identified_exploits[LOW_RELIABILITY]) == 0:
		print("\t[-] no exploits to verify for this kernel")

def kernelpop(exploit_db=None,mode="enumerate",uname=None):
	"""
	kernelpop()

	Runs the show
	:return:
	"""

	print(HEADER)
	if uname:
		kernel_v = get_kernel_version(uname=uname)
	else:
		kernel_v = get_kernel_version()
	identified_exploits = find_exploit_locally(kernel_v)
	display_identified_exploits(identified_exploits)

	if mode == "brute":
		brute_force_exploit(identified_exploits)


if __name__ == "__main__":
	kernelpop()

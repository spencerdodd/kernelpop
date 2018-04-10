import os
import re
import json
import subprocess
import platform
from pydoc import locate
from exploits.exploit import LinuxExploit, MacExploit
from src.kernels import KernelWindow
from constants import *
from distutils.version import StrictVersion

# gross...but lets us build a single file without dynamic module loads from filepath..maybe rework this

from exploits.linux.CVE20177308 import CVE20177308
from exploits.linux.CVE20171000379 import CVE20171000379
from exploits.linux.CVE20030961 import CVE20030961
from exploits.linux.CVE20091185 import CVE20091185
from exploits.linux.CVE20102959 import CVE20102959
from exploits.linux.CVE20104347 import CVE20104347
from exploits.linux.CVE20132094_32 import CVE20132094_32
from exploits.linux.CVE20132094_64 import CVE20132094_64
from exploits.linux.CVE20132094_semtex import CVE20132094_semtex
from exploits.linux.CVE20140038 import CVE20140038
from exploits.linux.CVE20140038_2 import CVE20140038_2
from exploits.linux.CVE20140196 import CVE20140196
from exploits.linux.CVE20143153 import CVE20143153
from exploits.linux.CVE20144014 import CVE20144014
from exploits.linux.CVE20144699 import CVE20144699
from exploits.linux.CVE20151328_32 import CVE20151328_32
from exploits.linux.CVE20151328_64 import CVE20151328_64
from exploits.linux.CVE20160728 import CVE20160728
from exploits.linux.CVE20162384 import CVE20162384
from exploits.linux.CVE20165195_32 import CVE20165195_32
from exploits.linux.CVE20165195_32_poke import CVE20165195_32_poke
from exploits.linux.CVE20165195_64 import CVE20165195_64
from exploits.linux.CVE20165195_64_poke import CVE20165195_64_poke
from exploits.linux.CVE20173630 import CVE20173630
from exploits.linux.CVE20175123 import CVE20175123
from exploits.linux.CVE20176074 import CVE20176074
from exploits.linux.CVE20171000112 import CVE20171000112
from exploits.linux.CVE20171000367 import CVE20171000367
from exploits.linux.CVE20171000370 import CVE20171000370
from exploits.linux.CVE20171000371 import CVE20171000371
from exploits.linux.CVE20171000372 import CVE20171000372
from exploits.linux.CVE20171000373 import CVE20171000373
from exploits.mac.CVE20164656 import CVE20164656
from exploits.mac.CVE20155889 import CVE20155889
from exploits.mac.NULLROOT import NULLROOT


class Kernel:
	def __init__(self, k_type, distro, name, base, specific, architecture, uname):
		self.k_type = k_type
		self.distro = distro
		self.name = name
		self.base = {
			"major": 		base["major"],
			"minor": 		base["minor"],
			"release": 		base["release"],
			"patch_level": 	base["patch_level"]
		}
		if specific:
			self.specific = {
				"major": 		specific["major"],
				"minor": 		specific["minor"],
				"release": 		specific["release"],
				"patch_level": 	specific["patch_level"]
			}
		else:
			self.specific = specific
		self.architecture = architecture
		self.uname = uname

		self.alert_kernel_discovery()

	def alert_kernel_discovery(self):
		if self.k_type == "windows":
			pass
		elif self.k_type == "mac" or self.k_type == "linux":
			if self.uname:
				color_print("[+] kernel ({}) identified as:".format(self.uname.replace("\n", "")), bold=True)
			else:
				color_print("[+] kernel identified as:".format(self.uname), bold=True)
			color_print("[base]\n\ttype:\t\t\t{}\n\tdistro:\t\t\t{}\n\tversion:\t\t{}-{}" \
						"\n\tarchitecture:\t\t{}".format(
				self.k_type,
				self.distro,
				".".join([str(self.base["major"]), str(self.base["minor"]), self.base["release"]]),
				self.base["patch_level"],
				self.architecture), bold=True)
			if self.specific:
				color_print("[specific]\n\ttype:\t\t\t{}\n\tdistro:\t\t\t{}\n\tversion:\t\t{}-{}" \
							"\n\tarchitecture:\t\t{}".format(
					self.k_type,
					self.distro,
					".".join([str(self.specific["major"]), str(self.specific["minor"]), str(self.specific["release"])]),
					self.specific["patch_level"],
					self.architecture), bold=True)
			else:
				color_print("[!] no specific distro kernel discovered...likelihood of false positives is high", color="yellow")
		else:
			exit(1)


def get_mac_version():
	"""
	Gets the mac operating system version vs. the kernel version
	:return:
	"""
	v_command = "sw_vers"
	mac_v = shell_results(v_command)[0].decode("utf-8")
	version_string = mac_v.split("\n")[1].split(":")[1]
	v_major = int(version_string.split(".")[0])
	v_minor = int(version_string.split(".")[1])
	try:
		v_release = int(version_string.split(".")[2])
	except:
		v_release = 0

	return v_major, v_minor, v_release


def get_kernel_version(uname=None, osx_ver=None):
	"""
	get_kernel_version()

	Determines the version of the kernel running on the underlying operating system. Uses the 'platform' package to
	ensure cross-compatibility between MacOS (OS X), Windows, and Linux hosts.

	:returns: Kernel object
	"""
	if uname:
		if osx_ver:
			os_type = "mac"
			split_ver = osx_ver.split(".")
			arch = architecture_from_uname(uname)
			kernel_base = {
				"major": split_ver[0],
				"minor": split_ver[1],
				"release": split_ver[2],
				"patch_level": "0"
			}
			kernel_specific = {
				"major": split_ver[0],
				"minor": split_ver[1],
				"release": split_ver[2],
				"patch_level": "0"
			}
			new_kernel = Kernel(
					os_type,
					"mac",
					"Darwin",
					kernel_base,
					kernel_specific,
					arch,
					uname
			)
			return new_kernel

		else:
			# so we can do everything except use OS commands. no worries, we'll just use the same methodology as
			# below, but just with the full uname. If we can't parse something that we have to have, we can decide
			# to either error out, or fill it with a default value and a warning
			os_type = os_type_from_full_uname(uname)
			if os_type == "mac":
				color_print("[!] sorry, I broke the mac stuff for now...gonna fix", color="red")

				exit(0)
			elif os_type == "linux":
				distro = distro_from_uname(uname)
				parsed_kernel_base, parsed_kernel_specific = get_kernel_version_from_uname(uname)
				if parsed_kernel_specific is None:
					if parsed_kernel_base is None:
						color_print("[!] could not grab a kernel version from given uname ({})".format(uname),
									color="red")
						color_print("[!] aborting...", color="red")
						exit(0)
					else:
						color_print("[!] could only get the kernel base...may not have accurate matches", color="yellow")

				# so we have the distro and the kernel version now, just need architecture
				arch = architecture_from_uname(uname)
				kernel_name = os_type

				# let's make our kernel
				new_kernel = Kernel(
					os_type,
					distro,
					kernel_name,
					parsed_kernel_base,
					parsed_kernel_specific,
					arch,
					uname
				)

				return new_kernel
			else:
				color_print("[!] could not determine operating system type...sorry", color="red")
				exit(0)

	else:
		"""
		otherwise, we have to parse from the system itself
		----------------------------------------------------------------------
		so our OS version info is coming from release, our kernel version should come from 'v' if available.
		if we don't have any data from 'v', we will fall back to 'r', but it will give us false positives so
		we should warn the user.
		"""
		os_info = 			shell_results("cat /etc/*release")[0].decode('utf-8')
		full_uname = 		shell_results("uname -a")[0].decode('utf-8')

		os_type = os_type_from_full_uname(full_uname)
		if os_type == "mac":
			os_type = "mac"
			major, minor, release = get_mac_version()
			arch = architecture_from_uname(full_uname)
			kernel_base = {
				"major": str(major),
				"minor": str(minor),
				"release": str(release),
				"patch_level": "0"
			}
			kernel_specific = {
				"major": str(major),
				"minor": str(minor),
				"release": str(release),
				"patch_level": "0"
			}
			new_kernel = Kernel(
					os_type,
					"mac",
					"Darwin",
					kernel_base,
					kernel_specific,
					arch,
					uname
			)
			return new_kernel

		elif os_type == "linux":
			distro = distro_from_os_info(os_info)
			print("[*] grabbing distro version and release from underlying OS ({})".format(distro))
			print("[*] grabbing kernel version from 'uname -a'")
			parsed_kernel_base, parsed_kernel_specific = get_kernel_version_from_uname(full_uname)
			if parsed_kernel_specific is None:
				if parsed_kernel_base is None:
					color_print("[!] could not grab a kernel version from given uname ({})".format(full_uname),
								color="red")
					color_print("[!] aborting...", color="red")
					exit(0)
				else:
					color_print("[!] could only get the kernel base...may not have accurate matches", color="yellow")

			# so we have the distro and the kernel version now, just need architecture
			arch = architecture_from_uname(full_uname)
			kernel_name = os_type

			# let's make our kernel
			new_kernel = Kernel(
				os_type,
				distro,
				kernel_name,
				parsed_kernel_base,
				parsed_kernel_specific,  # our specific kernel, set if exists
				arch,
				full_uname
			)

			return new_kernel

		else:
			color_print("[!] could not determine operating system type...sorry", color="red")
			exit(0)


def architecture_from_uname(uname_value):
	"""
	Parses out the architecture from the uname value. Fails to GENERIC

	:param uname_value: output of a uname command
	:return: ARCHITECTURE constant value (x86, x64, etc)
	"""
	for arch in architecture_needles["primary"].keys():
		if arch in uname_value:
			return architecture_needles["primary"][arch]
	for arch in architecture_needles["secondary"].keys():
		if arch in uname_value:
			return architecture_needles["secondary"][arch]

	return architecture_needles[ARCHITECTURE_DEFAULT]


def distro_from_uname(uname):
	"""
	Similar to distro_from_os_info. We can't rely on the VERSION string splitting though, so we need to find
	another way to parse out the versions from
	:param uname:
	:return:
	"""
	distro_re = re.compile("\~\d+\.\d+\.\d+\-\w+")
	potential_distros = distro_re.findall(uname) 			# should only be one, if it's more, you need a new regex
	if len(potential_distros) == 0:
		# we don't have a nice version string...so let's just spoof a number so we don't match overzealously
		potential_distros = ["~FAKEMAJOR.FAKEMINOR.FAKERELEASE-FAKEPATCH"]

	potential_version = potential_distros[0].split("~")[1].split(".")[0]

	for os_type in os_decision_tree.keys():
		if os_type in uname.lower():
			# try to find the version number in the version string
			for os_version in os_decision_tree[os_type].keys():
				if os_version == potential_version:
					return os_decision_tree[os_type][os_version]

			# we know the distro, but not the version, so return the generic version
			# of the distro
			return os_decision_tree[os_type][OS_DEFAULT_VAL_KEY]

	# we didn't find anything
	return GENERIC_LINUX


def distro_from_os_info(os_info):
	"""
	This needs to return the unique distro+version string from 'constants.py'

	$ cat /etc/*release
		PRETTY_NAME="Debian GNU/Linux 9 (stretch)"
		NAME="Debian GNU/Linux"
		VERSION_ID="9"
		VERSION="9 (stretch)"
		ID=debian
		HOME_URL="https://www.debian.org/"
		SUPPORT_URL="https://www.debian.org/support"
		BUG_REPORT_URL="https://bugs.debian.org/"

	:param os_info: output of 'cat /etc/*release'
	:return: unique distro + version string
	"""
	# implement decision tree
	for os_type in os_decision_tree.keys():
		if os_type in os_info.lower():
			# now that we have an os, we parse out the version number
			# first we try to split on
			if "VERSION_ID" in os_info:
				version_string = os_info.split("VERSION_ID")[1].split("\n")[0]
			elif "VERSION" in os_info:
				version_string = os_info.split("VERSION")[1].split("\n")[0]
			else:
				version_string = os_info

			# try to find the version number in the version string
			for os_version in os_decision_tree[os_type].keys():
				if os_version in version_string:
					return os_decision_tree[os_type][os_version]

			# we know the distro, but not the version, so return the generic version
			# of the distro
			return os_decision_tree[os_type][OS_DEFAULT_VAL_KEY]

	# we didn't find anything
	return GENERIC_LINUX


def get_kernel_version_from_uname(uname_value):
	"""
	More complex, needs to return the kernel version for a given 'uname -v' output:

		$ uname -v
		#1 SMP Debian 4.9.65-3+deb9u1 (2017-12-23)

	This should return two kernels, the linux base, and the distro specific. If there is only one, assign it as the
	base. If there are two (valid) kernels i.e., not higher than the MAX POSSIBLE MAJOR, assign the lower to the
	linux base, and the higher to specific

	:param uname_v: output of 'uname -v'
	:return: dictionary of kernel version, or None if we couldn't parse the value
	:return: one for base, one for specific
	"""
	# dynamically locate possible kernel versions by searching for the member of the " " split array that has more than
	# one '.' character in it

	# this regex: \d+.\d+.\d+-\w+
	# NOTE: will cut off patch level details like '+deb9u1' from a full patch value (3+deb9u1)
	with_patch = re.compile("\d+\.\d+\.\d+.\w+")
	possible_kernel_strings = with_patch.findall(uname_value)
	parsed_kernels = possible_kernels_from_strings(possible_kernel_strings)

	# now we find the kernel versions that don't have a major version
	# higher than KERNEL_MAJOR_VERSION_CAP. This allows us to easily parse out the linux versions like
	# Ubuntu16.04.1 from actual kernel values.
	possible_kernels = []
	for kernel in parsed_kernels:
		if not int(kernel["major"]) > KERNEL_MAJOR_VERSION_CAP:
			possible_kernels.append(kernel)

	# now we find the highest remaining kernel value. The kernel version will always be higher than the release
	# value
	# weird hacky comparison we take from KernelWindow comparisons that works lol
	fake_kernel = {"major": "0", "minor": "0", "release": "0"}
	highest_kernel = fake_kernel
	second_highest = fake_kernel
	for kernel in possible_kernels:
		highest_formatted_val = "{}.{}.{}".format(highest_kernel["major"], highest_kernel["minor"], highest_kernel["release"])
		current_formatted_val = "{}.{}.{}".format(kernel["major"], kernel["minor"], kernel["release"])
		if StrictVersion(current_formatted_val) >= StrictVersion(highest_formatted_val):
			second_highest = highest_kernel
			highest_kernel = kernel

	# if we didn't find a kernel, return None
	if highest_kernel == fake_kernel:
		highest_kernel = None

	if second_highest == fake_kernel:
		second_highest = highest_kernel
		highest_kernel = None

	return second_highest, highest_kernel


def possible_kernels_from_strings(kernel_strings):
	# iterate through all the possible kernel indexes and convert them into kernel dictionaries
	parsed_kernels = []
	for kernel_string in kernel_strings:
		split_kernel = kernel_string.split(".")

		major = split_kernel[0]
		minor = split_kernel[1]
		release = split_kernel[2].split("-")[0] # because our patch will be on the end of that

		kernel_version = {
			"major": major,
			"minor": minor,
			"release": release,
		}

		patch_level_included = len(kernel_string.split("-")) > 1
		if patch_level_included:
			patch_level = kernel_string.split("-")[1]

			kernel_version["patch_level"] = patch_level

		parsed_kernels.append(kernel_version)

	return parsed_kernels


def os_type_from_full_uname(full_uname):
	"""
	This should return one of "linux" or "mac". We use the full uname because it might have tidbits of info that
	are not found in separate commands.
	:param kernel_version: "uname -v" output
	:return: string
	"""
	if "darwin" in full_uname.lower():
		return "mac"
	elif "linux" in full_uname.lower():
		return "linux"
	else:
		return "unknown"


def pull_distro_version_from_uname(uname_output):
	for spaced in uname_output.split(" "):
		if "+" in spaced:
			return spaced

	return "not parsed"


def clean_parsed_version(parsed_version):
	"""
	Takes in a parsed version in the form Major.Minor.Release and cleans it of any appended garbage
	Appended garbage takes the form of stuff added on that wasn't split out on the '-' character

	:param parsed_version:
	:return:
	"""
	for idx, version_n in enumerate(parsed_version):
		parsed_version[idx] = version_n.split("-")[0]

	# check to make sure we got everything
	for version_n in parsed_version:
		if not version_n.isdigit():
			Exception("DIDN'T CLEAN VERSION PROPERLY")

	return parsed_version


def potentially_vulnerable(kernel_version, exploit_module):
	"""
	potentially_vulnerable(kernel_version, exploit_module)

	Identifies if a given kernel is vulnerable to a given exploit and in what capacity (i.e. Confirmed or Potential).
	Checks architecture requirements as well

	:param kernel_version: Kernel object
	:param exploit_module: Exploit object
	:return: string expressing the vulnerability state of the given Kernel object to the given Exploit object
	"""
	if kernel_version.architecture == exploit_module.architecture or \
					exploit_module.architecture == ARCHITECTURE_GENERIC:
		# if our kernel base is inside of the exploit module's base window, it may be vulnerable

		base_window_status = exploit_module.vulnerable_base.kernel_in_window(kernel_version.distro, kernel_version.base)
		if base_window_status is None:
			return NOT_VULNERABLE
		else:
			if kernel_version.specific:
				for vulnerable_window in exploit_module.vulnerable_kernels:
					vulnerable_window_status = vulnerable_window.kernel_in_window(kernel_version.distro, kernel_version.specific)
					if vulnerable_window_status is not None:
						for exploit_window in exploit_module.exploit_kernels:
							exploit_window_status = exploit_window.kernel_in_window(kernel_version.distro, kernel_version.specific)
							if exploit_window_status is not None:
								return exploit_window_status
						return vulnerable_window_status


				# return not vulnerable, because our specific version failed the exploit reqs
				return NOT_VULNERABLE
			else:
				return base_window_status

	else:
		return NOT_VULNERABLE


def find_exploit_locally(kernel_version):
	"""
	find_exploit_locally(Kernel kernel_version)

	Identifies potential exploits for the given kernel by dynamically loading exploit modules from the identified
	operating system's `exploit` dir and checking the kernel vs the list of vulnerable kernels in that exploit.

	:param kernel_version: Kernel() object containing kernel information
	:returns: array of arrays of exploit modules sorted in order of likelihood of success
		i.e. [ [high] [medium] [low] ]
	"""
	found_exploits = {
		EXPLOIT_AVAILABLE: [],
		VERSION_VULNERABLE: [],
		BASE_VULNERABLE: [],
		NOT_VULNERABLE: []
	}

	kernel_exploits_and_paths = [
		["linux", LINUX_EXPLOIT_PATH],
		["mac", MAC_EXPLOIT_PATH]
	]

	color_print("[*] matching kernel to known exploits")
	for idx,k_ex_path in enumerate(kernel_exploits_and_paths):
		if kernel_version.k_type == kernel_exploits_and_paths[idx][0]:
			all_exploits = [
				CVE20177308(),
				CVE20171000379(),
				CVE20030961(),
				CVE20091185(),
				CVE20102959(),
				CVE20104347(),
				CVE20132094_32(),
				CVE20132094_64(),
				CVE20132094_semtex(),
				CVE20140038(),
				CVE20140038_2(),
				CVE20140196(),
				CVE20143153(),
				CVE20144014(),
				CVE20144699(),
				CVE20151328_32(),
				CVE20151328_64(),
				CVE20160728(),
				CVE20162384(),
				CVE20165195_32(),
				CVE20165195_32_poke(),
				CVE20165195_64(),
				CVE20165195_64_poke(),
				CVE20173630(),
				CVE20175123(),
				CVE20176074(),
				CVE20171000112(),
				CVE20171000367(),
				CVE20171000370(),
				CVE20171000371(),
				CVE20171000372(),
				CVE20171000373(),
				CVE20164656(),
				CVE20155889(),
				NULLROOT(),
			]
			for exploit_instance in all_exploits:
				vuln_result = potentially_vulnerable(kernel_version, exploit_instance)
				if vuln_result == NOT_VULNERABLE:
					# bummer
					pass
				else:
					found_exploits[vuln_result].append(exploit_instance)

	return found_exploits


def display_exploits(exploits):
	"""

	:param ordered_exploits:
	:param begin_message:
	:param fail_message:
	:param color:
	:return:
	"""
	if total_exploits(exploits) > 0:
		color_print("[+] discovered {} possible exploits !".format(total_exploits(exploits)))

		# for confirmed vulnerabilities
		if len(exploits[EXPLOIT_AVAILABLE]) > 0:
			color_print("\t[[ distro kernel matched exploit available ]]", color="green")
			for high_exploit in exploits[EXPLOIT_AVAILABLE]:
				color_print("\t\t{}\t{}".format(high_exploit.name, high_exploit.brief_desc))
		if len(exploits[VERSION_VULNERABLE]) > 0:
			color_print("\t[[ distro kernel version vulnerable ]]", color="blue")
			for medium_exploit in exploits[VERSION_VULNERABLE]:
				color_print("\t\t{}\t{}".format(medium_exploit.name, medium_exploit.brief_desc))
		if len(exploits[BASE_VULNERABLE]) > 0:
			color_print("\t[[ base linux kernel vulnerable ]]", color="yellow")
			for low_exploit in exploits[BASE_VULNERABLE]:
				color_print("\t\t{}\t{}".format(low_exploit.name, low_exploit.brief_desc))
	else:
		color_print("[-] no exploits found for this kernel", color="red")


def exploit_individually(exploit_name):
	color_print("[*] attempting to perform exploitation with exploit {}".format(exploit_name))
	exploit_os = ["linux", "windows", "mac"]
	found_exploit = False
	for os_type in exploit_os:
		exploit_path_string = "exploits.{}.{}.{}".format(os_type, exploit_name, exploit_name)
		exploit_module = locate(exploit_path_string)
		if exploit_module:
			found_exploit = True
			exploit_module().exploit()
	if not found_exploit:
		color_print("[-] exploit {} was not found".format(exploit_name), color="red")


def total_exploits(exploits):
	total = 0
	levels = [EXPLOIT_AVAILABLE, VERSION_VULNERABLE, BASE_VULNERABLE]
	for level in levels:
		if level in exploits.keys():
			if len(exploits[level]) > 0:
				total += len(exploits[level])

	return total


def convert_to_digestible(exploit_list, digest="json"):
	if digest == "json":
		jsonified = {
			EXPLOIT_AVAILABLE: [],
			VERSION_VULNERABLE: [],
			BASE_VULNERABLE: []
		}

		for keytype in jsonified.keys():
			subset = exploit_list[keytype]
			for exploit in subset:
				jsonified[keytype].append(exploit.jsonify())
		return json.dumps(jsonified)


def write_digestible_to_file(file_to_write, contents):
	try:
		with open(file_to_write, "w") as digestfile:
			digestfile.write(contents)
	except Exception as e:
		color_print("[!] error writing results to file", color="red")
		color_print("\t{}".format(e), color="red")


def kernelpop(mode="enumerate", uname=None, exploit=None, osx_ver=None, digest=None):
	"""
	kernelpop()

	Runs the show
	:return:
	"""

	color_print(HEADER, color="blue", bold=True)
	if exploit:
		exploit_individually(str(exploit))
	else:
		if uname:
			if osx_ver:
				kernel_v = get_kernel_version(uname=uname, osx_ver=osx_ver)
			else:
				kernel_v = get_kernel_version(uname=uname)
		else:
			kernel_v = get_kernel_version()

		# if we don't have a kernel for some reason, exit
		if kernel_v is None:
			print('[!] exiting')
			exit(0)

		identified_exploits = find_exploit_locally(kernel_v)

		display_exploits(identified_exploits)

		if digest:
			digest_filepath = os.path.join(ROOT_DIR, "output.{}".format(digest))
			print("[*] dumping results to {} file ({}".format(digest, digest_filepath))
			digestible_results = convert_to_digestible(identified_exploits)
			write_digestible_to_file(digest_filepath, digestible_results)


if __name__ == "__main__":
	kernelpop()

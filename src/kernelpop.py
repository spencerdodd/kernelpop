import os
import re
import json
import subprocess
import platform
from pydoc import locate
from exploits.exploit import LinuxExploit, MacExploit
from src.kernels import KernelWindow
from functools import singledispatch
from constants import *
from distutils.version import StrictVersion

class Kernel:
	def __init__(self, type, distro, name, major_version, minor_version, release, patch_level, architecture, uname=False):
		self.type = type,
		self.distro = distro,
		self.name = name,
		self.major_version = major_version,
		self.minor_version = minor_version,
		self.release = release,
		self.patch_level = patch_level,
		self.architecture = architecture,
		self.uname = uname

		self.alert_kernel_discovery()

	def alert_kernel_discovery(self):
		if self.type == "linux":
			color_print("[+] kernel {} identified as:\n\ttype:\t\t\t{}\n\tdistro:\t\t\t{}\n\tversion:\t\t{}-{}" \
						"\n\tarchitecture:\t\t{}".format(
				self.uname, self.type, self.distro, ".".join([str(self.major_version), str(self.minor_version)]), self.release,
				self.architecture), bold=True)
		elif self.type == "mac":
			color_print("[+] kernel {} identified as:\n\ttype:\t\t\t{}\n\tversion:\t\t{}\n\tarchitecture:\t\t{}".format(
				self.uname, self.type, ".".join([str(self.major_version), str(self.minor_version), str(self.release)]),
				self.architecture), bold=True)
		elif self.type == "windows":
			pass
		else:
			exit(1)


def get_mac_version():
	"""
	Gets the mac operating system version vs. the kernel version
	:return:
	"""
	v_command = "sw_vers"
	mac_v = shell_results(v_command)[0].decode("utf-8")
	v_major = int(mac_v.split("\n")[1].split(":")[1].split(".")[0])
	v_minor = int(mac_v.split("\n")[1].split(":")[1].split(".")[1])
	try:
		v_release = int(mac_v.split("\n")[1].split(":")[1].split(".")[2])
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
			"""
			uname_pre = " ".join(uname.split(" ")[:2])
			uname_post = " ".join(uname.split(" ")[3:])
			uname_os_version = "{} {} {}".format(uname_pre, osx_ver, uname_post)
			return Kernel(uname_os_version, uname=True)
			"""
			color_print("[!] I broke the mac stuff...sorry", color="red")
			exit(0)
		else:
			# so we can do everything except use OS commands. no worries, we'll just use the same methodology as
			# below, but just with the full uname. If we can't parse something that we have to have, we can decide
			# to either error out, or fill it with a default value and a warning
			distro = distro_from_uname(uname)

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
		kernel_release = 	shell_results("uname -r")[0].decode('utf-8')
		kernel_version = 	shell_results("uname -v")[0].decode('utf-8')

		os_type = os_type_from_full_uname(full_uname)
		if os_type == "mac":
			color_print("[!] sorry, I broke the mac stuff for now...gonna fix", color="red")

		elif os_type == "linux":
			distro = distro_from_os_info(os_info)
			print("[*] parsing kernel version from underlying OS ({})".format(distro))
			print("[*[ grabbing kernel version from 'uname -v'")
			parsed_kernel_v = get_kernel_version_from_uname(kernel_version)
			if parsed_kernel_v is None:
				color_print("[!] we couldn't get the legit kernel version from ({})".format(kernel_version), color="yellow")
				color_print("[!] we're going to have to approximate with kernel release 'uname r'", color="yellow")
				color_print("[!] this has a high chance of leading to false positives")
				print("[*] attempting to approximate kernel version with kernel release")
				parsed_kernel_v = get_kernel_version_from_uname(kernel_release)

			if parsed_kernel_v is None:
				color_print("[!] could not parse kernel release from ({})".format(kernel_release), color="yellow")
				color_print("[*] attempting final kernel release/version grab from 'uname -a'")
				parsed_kernel_v = get_kernel_version_from_uname(full_uname)

			if parsed_kernel_v is None:
				color_print("[!] could not grab a semblance of kernel version from ({})".format(full_uname), color="yellow")
				color_print("[!] kernel version could not be parsed from underlying OS", color="red")
				color_print("[!] aborting...", color="red")
				exit(0)

			# so we have the distro and the kernel version now, just need architecture
			arch = architecture_from_uname(full_uname)

			# we're going to set the kernel name to the os_type, because I forgot if we even need that field
			kernel_name = os_type

			# now we can make and return our kernel!
			"""
			def __init__(self, type, distro, name, major_version, minor_version, release, patch_level, architecture,
						uname=False):
			"""
			new_kernel = Kernel(os_type,
				distro,
				kernel_name,
				parsed_kernel_v["major"],
				parsed_kernel_v["minor"],
				parsed_kernel_v["release"],
				None, 						# patch level, we'll set after
				arch
			)
			if "patch_level" in parsed_kernel_v.keys():
				new_kernel.patch_level = parsed_kernel_v["patch_level"]

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
	return None


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

	:param uname_v: output of 'uname -v'
	:return: dictionary of kernel version, or None if we couldn't parse the value
	"""
	# dynamically locate possible kernel versions by searching for the member of the " " split array that has more than
	# one '.' character in it

	# this regex: \d+.\d+.\d+-\w+
	with_patch = re.compile("\d+.\d+.\d+-\w+")
	possible_kernel_strings = with_patch.findall(uname_value)
	parsed_kernels = possible_kernels_from_strings(possible_kernel_strings)

	# now we find the kernel versions that don't have a major version
	# higher than KERNEL_MAJOR_VERSION_CAP. This allows us to easily parse out the linux versions like
	# Ubuntu16.04.1 from actual kernel values.
	possible_kernels = []
	for kernel in parsed_kernels:
		if not kernel["major"] > KERNEL_MAJOR_VERSION_CAP:
			possible_kernels.append(kernel)

	# now we find the highest remaining kernel value. The kernel version will always be higher than the release
	# value
	# weird hacky comparison we take from KernelWindow comparisons that works lol
	fake_kernel = {"major": "0", "minor": "0", "release": "0"}
	highest_kernel = fake_kernel
	for kernel in possible_kernels:
		highest_formatted_val = "{}.{}.{}".format(highest_kernel["major"], highest_kernel["minor"], highest_kernel["release"])
		current_formatted_val = "{}.{}.{}".format(kernel["major"], kernel["minor"], kernel["release"])
		if StrictVersion(current_formatted_val) > StrictVersion(highest_formatted_val):
			highest_kernel = kernel

	return highest_kernel


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
		vuln_results = []
		for kernel_window in exploit_module.vulnerable_kernels:
			vuln_results.append(kernel_window.kernel_in_window(kernel_version))
		for vuln_cat in [CONFIRMED_VULNERABLE, POTENTIALLY_VULNERABLE, NOT_VULNERABLE]:
			if vuln_cat in vuln_results:
				return vuln_cat
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
	confirmed = {
		HIGH_RELIABILITY: [],
		MEDIUM_RELIABILITY: [],
		LOW_RELIABILITY: []
	}
	potential = {
		HIGH_RELIABILITY: [],
		MEDIUM_RELIABILITY: [],
		LOW_RELIABILITY: []
	}
	found_exploits = {"confirmed": confirmed, "potential": potential}

	kernel_exploits_and_paths = [
		["linux", LINUX_EXPLOIT_PATH],
		["mac", MAC_EXPLOIT_PATH]
	]

	color_print("[*] matching kernel to known exploits")
	for idx,k_ex_path in enumerate(kernel_exploits_and_paths):
		if kernel_version.type == kernel_exploits_and_paths[idx][0]:
			all_exploits = os.listdir(kernel_exploits_and_paths[idx][1])
			for exploit_file in all_exploits:
				if exploit_file[-3:] == ".py" and "__init__" not in exploit_file:
					exploit_name = exploit_file.replace(".py", "")
					exploit_module = locate("exploits.{}.{}.{}".format(kernel_exploits_and_paths[idx][0],exploit_name, exploit_name))
					exploit_instance = exploit_module()
					if potentially_vulnerable(kernel_version, exploit_instance) == CONFIRMED_VULNERABLE:
						color_print("\t[+] found `confirmed` kernel exploit: {}".format(exploit_instance.name),
									color="green")
						found_exploits["confirmed"][exploit_instance.reliability].append(exploit_instance)
					elif potentially_vulnerable(kernel_version, exploit_instance) == POTENTIALLY_VULNERABLE:
						color_print("\t[+] found `potential` kernel exploit: {}".format(exploit_instance.name),
									color="yellow")
						found_exploits["potential"][exploit_instance.reliability].append(exploit_instance)
					else:
						del exploit_module

	return found_exploits


def find_exploit_remotely(kernel_version):
	"""

	:param kernel_version: dictionary of the kernel version returned from `get_kernel_version()`
	:return: array of unique exploit identifiers possible for this kernel
	"""
	pass


def brute_force_enumerate(identified_exploits):
	"""
	change enumeration to only cover potentials and move them to confirmed if they come back confirmed, otherwise
	drop them

	:param identified_exploits:
	:return:
	"""
	# TODO: read function description
	confirmed_vulnerable = {"high":[], "medium":[], "low":[]}
	color_print("[*] attempting to confirm all discovered exploits from most to least probable")
	if len(identified_exploits[HIGH_RELIABILITY]) > 0:
		color_print("\t[[ high reliability ]]", color="green")
		for high_exploit in identified_exploits[HIGH_RELIABILITY]:
			if high_exploit.determine_vulnerability():
				confirmed_vulnerable["high"].append(high_exploit)
	if len(identified_exploits[MEDIUM_RELIABILITY]) > 0:
		color_print("\t[[ medium reliability ]]", color="yellow")
		for medium_exploit in identified_exploits[MEDIUM_RELIABILITY]:
			if medium_exploit.determine_vulnerability():
				confirmed_vulnerable["medium"].append(medium_exploit)
	if len(identified_exploits[LOW_RELIABILITY]) > 0:
		color_print("\t[[ low reliability ]]", color="red")
		for low_exploit in identified_exploits[LOW_RELIABILITY]:
			if low_exploit.determine_vulnerability():
				confirmed_vulnerable["low"].append(low_exploit)
	if len(identified_exploits[HIGH_RELIABILITY]) == 0 and \
					len(identified_exploits[MEDIUM_RELIABILITY]) == 0 and \
					len(identified_exploits[LOW_RELIABILITY]) == 0:
		color_print("[-] no exploits to verify for this kernel", color="red")

	return confirmed_vulnerable


def brute_force_exploit(confirmed_exploits):
	color_print("\t[*] attempting to exploit confirmed exploits", color="blue")
	if len(confirmed_exploits[HIGH_RELIABILITY]) > 0:
		color_print("\t[[ high reliability ]]", color="green")
		for high_exploit in confirmed_exploits[HIGH_RELIABILITY]:
			high_exploit.exploit()
	if len(confirmed_exploits[MEDIUM_RELIABILITY]) > 0:
		color_print("\t[[ medium reliability ]]", color="yellow")
		for medium_exploit in confirmed_exploits[MEDIUM_RELIABILITY]:
			medium_exploit.exploit()
	if len(confirmed_exploits[LOW_RELIABILITY]) > 0:
		color_print("\t[[ low reliability ]]", color="red")
		for low_exploit in confirmed_exploits[LOW_RELIABILITY]:
			low_exploit.exploit()


def display_ordered_exploits(ordered_exploits, begin_message=None, fail_message=None, color=None):
	"""

	:param ordered_exploits:
	:param begin_message:
	:param fail_message:
	:param color:
	:return:
	"""
	if color:
		color_print(begin_message, color=color)

		# for confirmed vulnerabilities
		if len(ordered_exploits[HIGH_RELIABILITY]) > 0:
			color_print("\t[[ high reliability ]]", color=color)
			for high_exploit in ordered_exploits[HIGH_RELIABILITY]:
				color_print("\t\t{}\t{}".format(high_exploit.name, high_exploit.brief_desc), color=color)
		if len(ordered_exploits[MEDIUM_RELIABILITY]) > 0:
			color_print("\t[[ medium reliability ]]", color=color)
			for medium_exploit in ordered_exploits[MEDIUM_RELIABILITY]:
				color_print("\t\t{}\t{}".format(medium_exploit.name, medium_exploit.brief_desc), color=color)
		if len(ordered_exploits[LOW_RELIABILITY]) > 0:
			color_print("\t[[ low reliability ]]", color=color)
			for low_exploit in ordered_exploits[LOW_RELIABILITY]:
				color_print("\t\t{}\t{}".format(low_exploit.name, low_exploit.brief_desc), color=color)
		if len(ordered_exploits[HIGH_RELIABILITY]) == 0 and \
						len(ordered_exploits[MEDIUM_RELIABILITY]) == 0 and \
						len(ordered_exploits[LOW_RELIABILITY]) == 0:
			if fail_message:
				color_print(fail_message, color=color)
	else:
		color_print(begin_message)

		# for confirmed vulnerabilities
		if len(ordered_exploits[HIGH_RELIABILITY]) > 0:
			color_print("\t[[ high reliability ]]", color="green")
			for high_exploit in ordered_exploits[HIGH_RELIABILITY]:
				color_print("\t\t{}\t{}".format(high_exploit.name, high_exploit.brief_desc))
		if len(ordered_exploits[MEDIUM_RELIABILITY]) > 0:
			color_print("\t[[ medium reliability ]]", color="yellow")
			for medium_exploit in ordered_exploits[MEDIUM_RELIABILITY]:
				color_print("\t\t{}\t{}".format(medium_exploit.name, medium_exploit.brief_desc))
		if len(ordered_exploits[LOW_RELIABILITY]) > 0:
			color_print("\t[[ low reliability ]]", color="red")
			for low_exploit in ordered_exploits[LOW_RELIABILITY]:
				color_print("\t\t{}\t{}".format(low_exploit.name, low_exploit.brief_desc))
		if len(ordered_exploits[HIGH_RELIABILITY]) == 0 and \
						len(ordered_exploits[MEDIUM_RELIABILITY]) == 0 and \
						len(ordered_exploits[LOW_RELIABILITY]) == 0:
			if fail_message:
				color_print(fail_message, color="red")


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
	levels = [HIGH_RELIABILITY, MEDIUM_RELIABILITY, LOW_RELIABILITY]
	for level in levels:
		if len(exploits[level]) > 0:
			total += len(exploits[level])

	return total


@singledispatch
def to_serializable(val):
	"""Used by default."""
	return str(val)


@to_serializable.register(KernelWindow)
def ts_kw_exploit(val):
	"""Used if *val* is an instance of KernelWindow."""
	json_kw = {
		"distro": val.distro,
		"confirmation": val.confirmation,
		"lowest_major": val.lowest_major,
		"lowest_minor": val.lowest_minor,
		"lowest_release": val.lowest_release,
		"highest_major": val.highest_major,
		"highest_minor": val.highest_minor,
		"highest_release": val.highest_release
	}

	return json_kw


@to_serializable.register(LinuxExploit)
def ts_linux_exploit(val):
	"""Used if *val* is an instance of LinuxExploit."""

	json_exploit = {
		"name": val.name,
		"type": val.type,
		"brief_desc": val.brief_desc,
		"reliability": val.reliability,
		"vulnerable_kernels": json.dumps(val.vulnerable_kernels, default=ts_kw_exploit),
		"architecture": val.architecture,
		"source_c_path": val.source_c_path,
		"compilation_path": val.compilation_path,
		"compilation_command": val.compilation_command,
		"exploit_command": val.exploit_command
	}
	return json_exploit


def convert_to_digestible(exploit_list, digest="json"):
	if digest == "json":
		return json.dumps(exploit_list, default=ts_linux_exploit)


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

		identified_exploits = find_exploit_locally(kernel_v)
		display_ordered_exploits(identified_exploits["confirmed"],
			begin_message="[*] matched kernel to the following confirmed exploits",
			fail_message="[-] no confirmed exploits were discovered for this kernel")
		display_ordered_exploits(identified_exploits["potential"],
			begin_message="[*] matched kernel to the following potential exploits:",
			fail_message="[-] no potential exploits were discovered for this kernel", color="yellow")

		merged_exploits = {}
		for key_val in identified_exploits["confirmed"]:
			merged_exploits[key_val] = identified_exploits["confirmed"][key_val] + identified_exploits["potential"][key_val]

		if total_exploits(merged_exploits) > 0:
			if "brute" in mode:
				confirmed_vulnerable = brute_force_enumerate(merged_exploits)
				display_ordered_exploits(confirmed_vulnerable, begin_message="[+] confirmed exploits",
										 fail_message="[-] no exploits were confirmed for this kernel")
				if "exploit" in mode:
					brute_force_exploit(confirmed_vulnerable)

		if digest:
			digest_filepath = os.path.join(ROOT_DIR, "output.{}".format(digest))
			print("[*] dumping results to {} file ({}".format(digest, digest_filepath))
			digestible_results = convert_to_digestible(merged_exploits) 	# do we want 'confirmed vulnerable' instead?
			write_digestible_to_file(digest_filepath, digestible_results)


if __name__ == "__main__":
	kernelpop()

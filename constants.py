import os
import subprocess
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PLAYGROUND_PATH = os.path.join(ROOT_DIR, "playground")
LINUX_EXPLOIT_PATH = os.path.join(ROOT_DIR, "exploits", "linux")
LINUX_EXPLOIT_SOURCE_PATH = os.path.join(ROOT_DIR, "exploits", "linux", "source")
MAC_EXPLOIT_PATH = os.path.join(ROOT_DIR, "exploits", "mac")
MAC_EXPLOIT_SOURCE_PATH = os.path.join(ROOT_DIR, "exploits", "mac", "source")

HIGH_RELIABILITY = "high"
MEDIUM_RELIABILITY = "medium"
LOW_RELIABILITY = "low"

CONFIRMED_VULNERABLE = "confirmed_vulnerable"
POTENTIALLY_VULNERABLE = "potentially_vulnerable"
NOT_VULNERABLE = "not_vulnerable"

GENERIC_LINUX = "linux"

UBUNTU_GENERIC = "linuxubuntu"
UBUNTU_18 = "linuxubuntu18"
UBUNTU_17 = "linuxubuntu17"
UBUNTU_16 = "linuxubuntu16"
UBUNTU_15 = "linuxubuntu15"
UBUNTU_14 = "linuxubuntu14"
UBUNTU_13 = "linuxubuntu13"
UBUNTU_12 = "linuxubuntu12"
UBUNTU_11 = "linuxubuntu11"
UBUNTU_10 = "linuxubuntu10"
UBUNTU_9 = "linuxubuntu9"
UBUNTU_8 = "linuxubuntu8"
UBUNTU_7 = "linuxubuntu7"
UBUNTU_6 = "linuxubuntu6"

DEBIAN_GENERIC = "linuxdebian"
DEBIAN_10 = "linuxdebian10"
DEBIAN_9 = "linuxdebian9"
DEBIAN_8 = "linuxdebian8"
DEBIAN_7 = "linuxdebian7"
DEBIAN_UNSTABLE = "linuxdebian-unstable"

ARCH = "linuxarch"
ARCH_LTS = "linuxarchlts"

RHEL = "linuxrhel"
CENTOS = "linuxcentos"
FEDORA = "linuxfedora"
GENTOO = "linuxgentoo"
SOLARIS = "linuxsolaris"
OPENBSD = "linuxopenbsd"
NETBSD = "linuxnetbsd"

GENERIC_MAC = "mac"
DARWIN_16 = "macdarwin16"

ARCHITECTURE_DEFAULT = "ARCHITECTURE_DEFAULT"
ARCHITECTURE_GENERIC =  "generic"
ARCHITECTURE_x86_64 =   "x86_64"
ARCHITECTURE_amd64 =    "amd64"
ARCHITECTURE_i686 =     "i686"

# these are self referential, but they don't have to be
# the key val is the string we search for, but the identifier
# that we set above can be whatever. it's internal. It does
# need to reference the above structs because we use it
# for exploit matching that reference the same values set
# above

# we have priority and secondary because amd64 may be over-
# ridden by x86_64 even though amd64 is more descriptive
architecture_needles = {
	"primary": {
		"amd64": 				ARCHITECTURE_amd64
	},
	"secondary": {
		"x86_64": 				ARCHITECTURE_x86_64,
		"i686": 				ARCHITECTURE_i686,
	},
	ARCHITECTURE_DEFAULT: 	ARCHITECTURE_GENERIC,
}

OS_DEFAULT_VAL_KEY = "OS_DEFAULT_VAL_KEY"

os_decision_tree = {
	"ubuntu": {
		"18": UBUNTU_18,
		"17": UBUNTU_17,
		"16": UBUNTU_16,
		"15": UBUNTU_15,
		"14": UBUNTU_14,
		"13": UBUNTU_13,
		"12": UBUNTU_12,
		"11": UBUNTU_11,
		"10": UBUNTU_10,
		"9": UBUNTU_9,
		"8": UBUNTU_8,
		"7": UBUNTU_7,
		"6": UBUNTU_6,
		OS_DEFAULT_VAL_KEY: UBUNTU_GENERIC
	},
	"debian": {
		"10": DEBIAN_10,
		"9": DEBIAN_9,
		"8": DEBIAN_8,
		"7": DEBIAN_7,
		OS_DEFAULT_VAL_KEY: DEBIAN_GENERIC
	},
	"arch": {
		OS_DEFAULT_VAL_KEY: ARCH
	},
	"redhat": {
		OS_DEFAULT_VAL_KEY: RHEL
	},
	"gentoo": {
		OS_DEFAULT_VAL_KEY: GENTOO
	},
	"centos": {
		OS_DEFAULT_VAL_KEY: CENTOS
	},
	"fedora": {
		OS_DEFAULT_VAL_KEY: FEDORA
	},
	"solaris": {
		OS_DEFAULT_VAL_KEY: SOLARIS
	},
	"openbsd": {
		OS_DEFAULT_VAL_KEY: OPENBSD
	},
	"netbsd": {
		OS_DEFAULT_VAL_KEY: NETBSD
	},
}

USAGE_STRING = \
"""usage:
\t(default)\t\tpython3 kernelpop.py
\t(brute-mode)\tpython3 kernelpop.py -b
\t(exploit-mode)\tpython3 kernelpop.py -e {exploit name}
\t(input-mode)\tpython3 kernelpop.py -i
other:
\t(json output file) --dump json
\t(xml output file) --dump xml"""

HEADER = """
##########################
#  welcome to kernelpop  #
#                        #
# let's pop some kernels #
##########################
"""
class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'


def color_print(print_string, color=None, bold=False, underline=False, header=False):
	if color:
		color_string = ""
		colors = {
			"red": bcolors.FAIL,
			"yellow": bcolors.WARNING,
			"green": bcolors.OKGREEN,
			"blue": bcolors.OKBLUE,
		}
		if bold:
			color_string += bcolors.BOLD
		if underline:
			color_string += bcolors.UNDERLINE,
		if header:
			color_string += bcolors.HEADER
		color_string += colors[color] + print_string + bcolors.ENDC
		print(color_string)
	else:
		print(print_string)


def shell_results(shell_command):
	p = subprocess.Popen(
		shell_command,
		stdin=subprocess.PIPE,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		shell=True
	)
	result = p.communicate()
	return result
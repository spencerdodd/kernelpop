import os
import subprocess
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PLAYGROUND_PATH = "/tmp"
HIGH_RELIABILITY = "high"
MEDIUM_RELIABILITY = "medium"
LOW_RELIABILITY = "low"

"""

    * EXPLOIT AVAILABLE:    PoC exploit supports the specific OS version
    * VERSION VULNERABLE:   specific OS version is vulnerable (vendor confirmed)
    * BASE VULNERABLE:      the base linux kernel is in the vulnerable base range
    * NOT VULNERABLE:       the base kernel is outside the vulnerable range
"""

EXPLOIT_AVAILABLE = 	"exploit_available"
VERSION_VULNERABLE = 	"version_vulnerable"
BASE_VULNERABLE = 		"base_vulnerable"
NOT_VULNERABLE = 		"not_vulnerable"

GENERIC_LINUX = "linux"

KERNEL_MAJOR_VERSION_CAP = 4

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
UBUNTU_5 = "linuxubuntu5"
UBUNTU_4 = "linuxubuntu4"
UBUNTU_3 = "linuxubuntu3"
UBUNTU_2 = "linuxubuntu2"
UBUNTU_1 = "linuxubuntu1"

"""
1.1 	Buzz 	1996-06-17 	Buzz Lightyear
1.2 	Rex 	1996-12-12 	Rex (the T-Rex)
1.3 	Bo 	1997-06-05 	Bo Peep
2.0 	Hamm 	1998-07-24 	Hamm (the pig)
2.1 	Slink 	1999-03-09 	Slinky Dog
2.2 	Potato 	2000-08-15 	Mr Potato Head
3.0 	Woody 	2002-07-19 	Woody the cowboy
3.1 	Sarge 	2005-06-06 	Sarge from the Bucket O' Soldiers
4.0 	Etch 	2007-04-08 	Etch, the Etch-A-Sketch
5.0 	Lenny 	2009-02-14 	Lenny, the binoculars
6.0 	Squeeze 	2011-02-06 	Squeeze toy aliens
7 	Wheezy 	2013-05-04 	Wheezy the penguin
8 	Jessie 	2015-04-26 	Jessie the cowgirl
9 	Stretch 	2017-06-17 	Rubber octopus from Toy Story 3
10 	Buster 	not yet released 	Andy's pet dog
11 	Bullseye 	Not yet released 	Woody's horse
	Sid		"unstable"	The next doorneighbour
"""

DEBIAN_GENERIC = "linuxdebian"
DEBIAN_10 = "linuxdebian10"
DEBIAN_9 = "linuxdebian9"
DEBIAN_8 = "linuxdebian8"
DEBIAN_7 = "linuxdebian7"
DEBIAN_6 = "linuxdebian6"
DEBIAN_5 = "linuxdebian5"
DEBIAN_4 = "linuxdebian4"
DEBIAN_3 = "linuxdebian3"
DEBIAN_2 = "linuxdebian2"
DEBIAN_1 = "linuxdebian1"
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
SUSE = "linuxsuse"

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
		"6": DEBIAN_6,
		"5": DEBIAN_5,
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
	"suse": {
		OS_DEFAULT_VAL_KEY: SUSE
	}
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


def jsonify_kernel_window_list(kernel_window_list):
	jsonified = []
	for kernel_window in kernel_window_list:
		jsonified.append(kernel_window.jsonify())
	return jsonified

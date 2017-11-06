import os
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PLAYGROUND_PATH = os.path.join(ROOT_DIR, "playground")
LINUX_EXPLOIT_PATH = os.path.join(ROOT_DIR, "exploits", "linux")
HIGH_RELIABILITY = "high"
MEDIUM_RELIABILITY = "medium"
LOW_RELIABILITY = "low"

CONFIRMED_VULNERABLE = "confirmed_vulnerable"
POTENTIALLY_VULNERABLE = "potentially_vulnerable"
NOT_VULNERABLE = "not_vulnerable"

GENERIC_LINUX = "linux"

UBUNTU_GENERIC = "linuxubuntu"
UBUNTU_17 = "linuxubuntu17"
UBUNTU_17_LTS = "linuxubuntu17lts"
UBUNTU_16 = "linuxubuntu16"
UBUNTU_16_LTS = "linuxubuntu16lts"
UBUNTU_15 = "linuxubuntu15"
UBUNTU_15_LTS = "linuxubuntu15lts"
UBUNTU_14 = "linuxubuntu14"
UBUNTU_14_LTS = "linuxubuntu14lts"
UBUNTU_13 = "linuxubuntu13"
UBUNTU_12 = "linuxubuntu12"
UBUNTU_12_LTS = "linuxubuntu12lts"
UBUNTU_10 = "linuxubuntu10"
UBUNTU_10_LTS = "linuxubuntu10lts"
UBUNTU_9 = "linuxubuntu9"
UBUNTU_9_LTS = "linuxubuntu9lts"
UBUNTU_8 = "linuxubuntu8"
UBUNTU_8_LTS = "linuxubuntu8lts"
UBUNTU_7 = "linuxubuntu7"
UBUNTU_7_LTS = "linuxubuntu7lts"
UBUNTU_6 = "linuxubuntu6"
UBUNTU_6_LTS = "linuxubuntu6lts"

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

ARCHITECTURE_GENERIC =  "generic"
ARCHITECTURE_x86_64 =   "x86_64"
ARCHITECTURE_amd64 =    "amd64"
ARCHITECTURE_i386 =     "i386"

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
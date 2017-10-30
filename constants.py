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

GENERIC_LINUX = "generic-linux"

UBUNTU_GENERIC = "ubuntu"
UBUNTU_17 = "ubuntu17"
UBUNTU_17_LTS = "ubuntu17lts"
UBUNTU_16 = "ubuntu16"
UBUNTU_16_LTS = "ubuntu16lts"
UBUNTU_15 = "ubuntu15"
UBUNTU_15_LTS = "ubuntu15lts"
UBUNTU_14 = "ubuntu14"
UBUNTU_14_LTS = "ubuntu14lts"
UBUNTU_13 = "ubuntu13"
UBUNTU_12 = "ubuntu12"
UBUNTU_12_LTS = "ubuntu12lts"
UBUNTU_10 = "ubuntu10"
UBUNTU_10_LTS = "ubuntu10lts"
UBUNTU_9 = "ubuntu9"
UBUNTU_9_LTS = "ubuntu9lts"
UBUNTU_8 = "ubuntu8"
UBUNTU_8_LTS = "ubuntu8lts"
UBUNTU_7 = "ubuntu7"
UBUNTU_7_LTS = "ubuntu7lts"
UBUNTU_6 = "ubuntu6"
UBUNTU_6_LTS = "ubuntu6lts"

DEBIAN_GENERIC = "debian"
DEBIAN_8 = "debian8"
DEBIAN_7 = "debian7"
DEBIAN_UNSTABLE = "debian-unstable"

ARCH = "arch"
ARCH_LTS = "archlts"

RHEL = "rhel"
CENTOS = "centos"
GENTOO = "gentoo"

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
import os
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PLAYGROUND_PATH = os.path.join(ROOT_DIR, "playground")
LINUX_EXPLOIT_PATH = os.path.join(ROOT_DIR, "exploits", "linux")
HIGH_RELIABILITY = "high"
MEDIUM_RELIABILITY = "medium"
LOW_RELIABILITY = "low"
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
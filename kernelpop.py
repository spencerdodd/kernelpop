import sys
from src.kernelpop import kernelpop
from constants import color_print, USAGE_STRING


def main():
	if len(sys.argv) < 2:
		kernelpop()
	# brute force all discovered exploits
	elif sys.argv[1] == "-b":
		kernelpop(mode="brute-enumerate")
	elif sys.argv[1] == "-e" and len(sys.argv) > 2:
		kernelpop(mode="exploit", exploit=sys.argv[2])
	elif sys.argv[1] == "-i":
		uname = input("Please enter uname: ")
		if "darwin" in str(uname).lower():
			color_print("[!] macs require additional input", color="yellow")
			osx_ver = input("[*] Please enter the OSX `ProductVersion`. It is found in 2nd line of output of `sw_vers` command: ")
			if len(str(osx_ver).split(".")) != 3:
				color_print("[-] OSX version input is not correct (Major.Minor.Release i.e 10.9.5)", color="red")
				exit(1)
			kernelpop(mode="input", uname=uname, osx_ver=osx_ver)
		else:
			kernelpop(mode="input", uname=uname)
	else:
		color_print("[!] please format your arguments properly", color="yellow")
		color_print(USAGE_STRING)
		color_print("[-] closing ...", color="red")


if __name__ == "__main__":
	main()
import sys
from src.kernelpop import kernelpop


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
			print("[!] macs require additional input")
			osx_ver = input("[*] Please enter the OSX version. It is found in 2nd line of output of `sw_vers` command: ")
			kernelpop(mode="input", uname=uname, osx_ver=osx_ver)
		else:
			kernelpop(mode="input", uname=uname)


if __name__ == "__main__":
	main()
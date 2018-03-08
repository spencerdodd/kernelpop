import sys
from src.kernelpop import kernelpop
from constants import color_print, USAGE_STRING


def main():

	# parse out whether we want a digestible output (json, xml)
	digest_type = None
	if "--digest" in sys.argv:
		if "json" in sys.argv:
			print("[*] outputting results in json digestible format")
			digest_type = "json"
		elif "xml" in sys.argv:
			print("[*] sorry, only json digestible output is supported at the moment (--digest json)")
			exit(0)

	if len(sys.argv) < 2:
		kernelpop()
	# brute force all discovered exploits
	elif "-b" in sys.argv[1:3]:
		kernelpop(mode="brute-enumerate", digest=digest_type)
	elif "-e" in sys.argv[1:3] and len(sys.argv) > 2:
		kernelpop(mode="exploit", exploit=sys.argv[2], digest=digest_type)
	elif "-i" in sys.argv[1:3]:
		color_print("[*] please note, vulnerability detection is not as accurate by uname alone", color="yellow")
		color_print("\tconsider running locally on the machine to be tested to get a more accurate reading", color="yellow")
		uname = input("Please enter uname: ")
		if "darwin" in str(uname).lower():
			color_print("[!] macs require additional input", color="yellow")
			osx_ver = input("[*] Please enter the OSX `ProductVersion`. It is found in 2nd line of output of `sw_vers` command: ")
			if len(str(osx_ver).split(".")) != 3:
				color_print("[-] OSX version input is not correct (Major.Minor.Release i.e 10.9.5)", color="red")
				exit(1)
			kernelpop(mode="input", uname=uname, osx_ver=osx_ver, digest=digest_type)
		else:
			kernelpop(mode="input", uname=uname, digest=digest_type)
	# if only --digest <option> is passed
	elif "--digest" in sys.argv[1:3]:
		kernelpop(digest=digest_type)
	else:
		color_print("[!] please format your arguments properly", color="yellow")
		color_print(USAGE_STRING)
		color_print("[-] closing ...", color="red")


if __name__ == "__main__":
	main()
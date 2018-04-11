import sys
from src.kernelpop import kernelpop
from constants import *

# hacky rebind of input so we can use existing input() code for python2 and python3
try:
	input = raw_input
except NameError:
	pass


def main():
	color_print(HEADER, color="blue", bold=True)
	# parse out whether we want a digestible output (json, xml)
	digest_type = None
	if "--digest" in sys.argv:
		digest_index = sys.argv.index("--digest")
		try:
			digest_type = str(sys.argv[digest_index + 1])
		except IndexError:
			color_print("[!] please enter a digest output type", color="red")
			exit(1)
		if digest_type == "json":
			color_print("[*] outputting results in json digestible format", color="blue")
			digest_type = "json"
		else:
			color_print("[*] sorry, only json digestible output is supported at the moment (--digest json)", color="red")
			exit(0)

		# delete the options from sys.argv
		del sys.argv[digest_index]
		del sys.argv[digest_index]

	playground_path = PLAYGROUND_PATH

	if "-p" in sys.argv:
		playground_index = sys.argv.index("-p")
		new_playground = str(sys.argv[playground_index + 1])
		color_print("[*] setting PLAYGROUND_PATH to ({})".format(new_playground), color="blue")
		playground_path = new_playground
		if playground_path == new_playground:
			color_print("\t[+] PLAYGROUND_PATH={}".format(playground_path), color="green")
		else:
			color_print("\t[!] could not set PLAYGROUND_PATH", color="red")

		# first delete deletes -p, second delete deletes the path
		del sys.argv[playground_index]
		del sys.argv[playground_index]

	# running the show

	if len(sys.argv) < 2:
		kernelpop(playground=playground_path, digest=digest_type)

	elif "-e" in sys.argv[1:3] and len(sys.argv) > 2:
		# dump the exploit source to disk
		if "-d" in sys.argv:
			kernelpop(mode="dump", exploit=sys.argv[2], playground=playground_path, digest=digest_type)
			pass
		else:
			kernelpop(mode="exploit", exploit=sys.argv[2], playground=playground_path, digest=digest_type)
	elif "-i" in sys.argv[1:3] or "-u" in sys.argv[1:3]:
		color_print("[*] please note, vulnerability detection is not as accurate by uname alone", color="yellow")
		color_print("\tconsider running locally on the machine to be tested to get a more accurate reading", color="yellow")
		if "-i" in sys.argv[1:3]:
			uname = input("Please enter uname: ")
			if "darwin" in str(uname).lower():
				color_print("[!] macs require additional input", color="yellow")
				osx_ver = input("[*] Please enter the OSX `ProductVersion`. It is found in 2nd line of output of `sw_vers` command: ")
				if len(str(osx_ver).split(".")) != 3:
					color_print("[-] OSX version input is not correct (Major.Minor.Release i.e 10.9.5)", color="red")
					exit(1)
				kernelpop(mode="input", uname=uname, osx_ver=osx_ver, playground=playground_path, digest=digest_type)
			else:
				kernelpop(mode="input", uname=uname, playground=playground_path, digest=digest_type)
		else:
			# support for command line input of uname with '-u' flag
			uname = " ".join(sys.argv[2:])
			if "darwin" in str(uname).lower():
				color_print("[!] cannot enumerate mac from uname alone...please use interactive-mode (-i)", color="red")
				exit(1)
			color_print("[*] processing uname: {}".format(uname), color="yellow")
			kernelpop(mode="input", uname=uname, playground=playground_path, digest=digest_type)
	else:
		color_print("[!] please format your arguments properly", color="yellow")
		color_print(USAGE_STRING)
		color_print("[-] closing ...", color="red")


if __name__ == "__main__":
	main()
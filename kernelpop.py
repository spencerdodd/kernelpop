import sys
from src.kernelpop import kernelpop


def main():
	if len(sys.argv) < 2:
		kernelpop()
	# brute force all discovered exploits
	elif sys.argv[1] == "-b":
		kernelpop(mode="brute-enumerate")
	elif sys.argv[1] == "-i":
		uname = input("Please enter uname: ")
		kernelpop(mode="input", uname=uname)


if __name__ == "__main__":
	main()
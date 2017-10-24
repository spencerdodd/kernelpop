import sys
from src.kernelpop import kernelpop


def main():
	if len(sys.argv) < 2:
		kernelpop()
	# brute force all discovered exploits
	elif sys.argv[1] == "-b":
		kernelpop(mode="brute")


if __name__ == "__main__":
	main()
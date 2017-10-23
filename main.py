from src.kernelpop import kernelpop
from exploits.linux.CVE201710012 import exploit


def practice_pop():
	exploit()
def main():
	kernelpop()
	practice_pop()

if __name__ == "__main__":
	main()
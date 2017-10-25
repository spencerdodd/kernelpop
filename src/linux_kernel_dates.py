"""
Dictionary containing minor/release dates for each distribution in order to more accurately nail down potential
windows of vulnerability. It will be possible to get a kernel version (or window range) from a date, allowing you
to search for potentially vulnerable distro release windows for a vulnerability given its public release date.

i.e.
	- if a vuln came out October 2017, it is possible that all kernels that came before it are vulnerable
	- it is possible that they are not, but quieter false positives are better than false negatives when it
		comes to kernel exploits (at least in my opinion?)

Format for dates is YYYY-MM-DD (most superior date time format)


Source:
	Ubuntu: https://en.wikipedia.org/wiki/Ubuntu_version_history
	Debian: https://en.wikipedia.org/wiki/Debian_version_history
	Fedora: https://en.wikipedia.org/wiki/Fedora_version_history
"""

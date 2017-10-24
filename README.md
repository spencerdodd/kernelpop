# kernelpop

kernelpop is a framework for performing automated kernel exploitation on Windows, Linux, and Mac hosts.

example run:

```
$ python kernelpop.py

##########################
# welcome to kernelpop   #
#                        #
# let's pop some kernels #
##########################

[+] underlying os identified as a linux variant
[+] kernel Linux-4.10.0-37-generic-x86_64-with-Ubuntu-16.04-xenial identified as:
	type:			linux
	distro:			ubuntu
	version:		4.10-37
	architecture:	x86_64
[*] matching kernel to known exploits
	[+] found potential kernel exploit: CVE-2009-1185
[*] identified exploits
	[[ high reliability ]]
		CVE-2009-1185	udev before 1.4.1 does not verify whether a NETLINK message originates from kernel space, which allows local users to gain privileges by sending a NETLINK message from user space.
	[[ medium reliability ]]
	[[ low reliability ]]
```

### workflow

The typical flow from run to pop is as follows:

* determine kernel version
* find exploit for discovered kernel
* check for exploit prerequisite conditions
* find any necessary values (paths, environmental conditions, etc.)
* alter source code with dynamic values
* compile updated source to `playground` with necessary flags
* run exploit with required command structure
* ???
* profit


### exploit sources

`https://www.exploit-db.com/local/`

`https://github.com/SecWiki/linux-kernel-exploits`

`https://github.com/SecWiki/windows-kernel-exploits`
# kernelpop

kernelpop is a framework for performing automated kernel exploitation on Linux, Mac, and Windows hosts.

Currently the project only functions with `python3`. I am undecided as to whether I will make this backwards 
compatible. As it stands, the `brute` mode is set to prepare, compile, and runs exploits in order to confirm an
exploitable kernel. This functionality, at the moment, is only functional on the box the program is run on. As it
is a fairly large project to bring on to someone else's computer and makes considerably noise when compiling and 
checking exploit attempts, it would be poor OPSEC to use in an actual engagement. The `input` mode allows you to
perform enumeration with just the output of a `uname -a` command which makes it useful as a host-side enumeration tool. 
At some point in the future, I would like to integrate it into my other project 
[pysploit](https://github.com/spencerdodd/pysploit) for enumeration and reckless, noisy, brute-forcing

tested just on Ubuntu as of 10-24-2017

### default enumeration mode

```
﻿exploit@ubuntuexploit:~/Desktop/kernelpop$ python3 kernelpop.py

##########################
#  welcome to kernelpop  #
#                        #
# let's pop some kernels #
##########################

[+] underlying os identified as a linux variant
[+] kernel Linux-4.10.0-28-generic-x86_64-with-Ubuntu-16.04-xenial identified as:
	type:			linux
	distro:			ubuntu
	version:		4.10-28
	architecture:	x86_64
[*] matching kernel to known exploits
	[+] found potential kernel exploit: CVE-2009-1185
[*] identified exploits
	[[ high reliability ]]
		CVE-2009-1185	udev before 1.4.1 NETLINK user space priv esc
```

### input mode

```
﻿exploit@ubuntuexploit:~/Desktop/kernelpop$ uname -a
Linux ubuntuexploit 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
exploit@ubuntuexploit:~/Desktop/kernelpop$ python3 kernelpop.py -i
Please enter uname: Linux ubuntuexploit 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

##########################
#  welcome to kernelpop  #
#                        #
# let's pop some kernels #
##########################

[+] underlying os identified as a linux variant
[+] kernel Linux ubuntuexploit 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux identified as:
	type:			linux
	distro:			ubuntu
	version:		4.10-28
	architecture:	x86_64
[*] matching kernel to known exploits
	[+] found potential kernel exploit: CVE-2009-1185
[*] identified exploits
	[[ high reliability ]]
		CVE-2009-1185	udev before 1.4.1 NETLINK user space priv esc
```

### brute-force mode
```
﻿exploit@ubuntuexploit:~/Desktop/kernelpop$ python3 kernelpop.py -b

##########################
#  welcome to kernelpop  #
#                        #
# let's pop some kernels #
##########################

[+] underlying os identified as a linux variant
[+] kernel Linux-4.10.0-28-generic-x86_64-with-Ubuntu-16.04-xenial identified as:
	type:			linux
	distro:			ubuntu
	version:		4.10-28
	architecture:	x86_64
[*] matching kernel to known exploits
	[+] found potential kernel exploit: CVE-2009-1185
[*] identified exploits
	[[ high reliability ]]
		CVE-2009-1185	udev before 1.4.1 NETLINK user space priv esc
[*] attempting brute force of all discovered exploits from most to least probable
	[[ high reliability ]]
	[*] attempting to exploit CVE-2009-1185
	[-] exploitation failed: not vulnerable: (1: udevd: not found)
	[-] exploitation failed: not vulnerable to CVE20091185
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
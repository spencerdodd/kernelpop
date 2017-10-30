# kernelpop

kernelpop is a framework for performing automated kernel exploit enumeration on Linux, Mac, and Windows hosts.

![old-kernel](https://github.com/spencerdodd/kernelpop/blob/master/img/old_kernel.png "old kernel img")

### requirements

`python3`

---

### currently supported CVE's:

*`CVE-2017-1000367`

*`CVE-2017-1000112`

*`CVE-2017-7308`

*`CVE-2017-6074`

*`CVE-2017-5123`

*`CVE-2016-5195`

*`CVE-2016-2384`

*`CVE-2016-0728`

*`CVE-2015-7547`

*`CVE-2015-1328`

*`CVE-2014-4699`

*`CVE-2014-4014`

*`CVE-2014-3153`

*`CVE-2014-0196`

*`CVE-2009-1185`

---

# run modes

### default mode

The `default` mode runs with the command `python3 kernelpop.py`. This processes information about the
host kernel and compares it to the known kernel exploits available to the program. It then outputs a list of
potentially useful vulnerabilities and attached exploits.

![default-mode](https://github.com/spencerdodd/kernelpop/blob/master/img/default_mode.png "default img")

### brute-enumeration mode

The `brute-enumeration` mode performs the same checks, but then
goes beyond and checks the computer for exploit prerequisites to see if the operating system is set up in the
required vulnerable state for successful exploitation. 

![brute-mode](https://github.com/spencerdodd/kernelpop/blob/master/img/brute_mode.png "brute img")

### input mode

The `input` mode allows you to perform enumeration with just the output of a `uname -a` command, 
which makes it useful as a host-side enumeration tool.

![input-mode](https://github.com/spencerdodd/kernelpop/blob/master/img/input_mode.png "input img")

One feature currently only partially implemented is `brute-exploit` mode. This is set to prepare, compile, and run
exploits in order to confirm an exploitable kernel. However, as of now it would only run on the box the program is 
executed on. Given that this is a fairly large project to bring on to someone else's computer, and makes considerable 
noise when compiling and checking exploit attempts, it would be poor OPSEC to use in an actual engagement. At some 
point in the future, I would like to integrate it into my other project 
[pysploit](https://github.com/spencerdodd/pysploit) for enumeration and the reckless, noisy, exploity `brute-exploit`
mode.

### exploit sources

`https://github.com/SecWiki/linux-kernel-exploits`

`https://www.exploit-db.com/local/`

`https://github.com/SecWiki/windows-kernel-exploits`
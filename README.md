# kernelpop

kernelpop is a framework for performing automated kernel exploit enumeration on Linux, Mac, and Windows hosts.

### example of enumeration to root

[![got-root](https://asciinema.org/a/U1das0JfT8dMbYRWmvpRDVqpW.png "got-root")](https://asciinema.org/a/U1das0JfT8dMbYRWmvpRDVqpW)

---

### NOTE:

Since it seems like this project is getting some clones / views, I should say this is a work in progress. I'm taking 
class and working fulltime so getting programming time is sporadic. That said, I am actively maintaining and adding
features. Please let me know if you find any issues with the project.

Thanks!

---

### requirements

`python3`

---

# run modes

### default mode

The `default` mode runs with the command `python3 kernelpop.py`. This processes information about the
host kernel and compares it to the known kernel exploits available to the program. It then outputs a list of
potentially useful vulnerabilities and attached exploits.

[![default-mode](https://asciinema.org/a/JIi7d52Le8YoBPpw06jeoHvSJ.png "default asciinema")](https://asciinema.org/a/JIi7d52Le8YoBPpw06jeoHvSJ)


### exploit mode (new!)

The `exploit` mode is run with the `-e` flag. This dynamically compiles and runs the exploit source code with stdio
interactions inside the program! It can catch interrupts from short-stopped attempts as well

[![exploit-mode](https://asciinema.org/a/a8z5dCqOmemSPznuZPDxp7aAW.png)](https://asciinema.org/a/a8z5dCqOmemSPznuZPDxp7aAW)

### brute-enumeration mode

The `brute-enumeration` mode performs the same checks, but then
goes beyond and checks the computer for exploit prerequisites to see if the operating system is set up in the
required vulnerable state for successful exploitation. 

[![brute-mode](https://asciinema.org/a/7X4fKZN9R2pJKUrqmFZsK33fd.png "brute asciinema")](https://asciinema.org/a/7X4fKZN9R2pJKUrqmFZsK33fd)

### input mode

The `input` mode allows you to perform enumeration with just the output of a `uname -a` command, 
which makes it useful as a host-side enumeration tool.

[![input-mode](https://asciinema.org/a/8gBOYZi5vVcHJmxKqRdyLizy2.png "input asciinema")](https://asciinema.org/a/8gBOYZi5vVcHJmxKqRdyLizy2)

---

### currently supported CVE's:

* `CVE-2017-1000379`

* `CVE-2017-1000373`

* `CVE-2017-1000372`

* `CVE-2017-1000371`

* `CVE-2017-1000370`

* `CVE-2017-1000367`

* `CVE-2017-1000112`

* `CVE-2017-7308`

* `CVE-2017-6074`

* `CVE-2017-5123`

* `CVE-2016-5195`

* `CVE-2016-2384`

* `CVE-2016-0728`

* `CVE-2015-1328`

* `CVE-2014-4699`

* `CVE-2014-4014`

* `CVE-2014-3153`

* `CVE-2014-0196`

* `CVE-2009-1185`

---

### exploit sources

`https://github.com/SecWiki/linux-kernel-exploits`

`http://exploit-db.com/`

`https://www.exploit-db.com/local/`

`https://github.com/SecWiki/windows-kernel-exploits`

### historical distro sources

Debian

* [debian releases](http://cdimage.debian.org/cdimage/archive/)


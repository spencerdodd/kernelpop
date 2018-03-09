# kernelpop

kernelpop is a framework for performing automated kernel vulnerability enumeration and exploitation 
on the following operating systems:

- [x] Linux

- [x] Mac

### To Do

- [ ] include patch levels in vulnerable window comparisons

- [ ] add way to override detected settings in case of incorrect parsing or adversarial settings

### example of enumeration to root (Linux)

![got-root](img/final.gif)

### requirements

`python3`

---

# usage

```
run modes:
	(default)	python3 kernelpop.py
	(exploit-mode)	python3 kernelpop.py -e {exploit name}
	(input-mode)	python3 kernelpop.py -i
other:
	(json output file) --dump json
	(xml output file) --dump xml
```

### default mode (passive)

The `default` mode processes information about the host kernel and compares it to the known kernel exploits available
to the program. It then outputs a list of potentially useful vulnerabilities and attached exploits.

### exploit mode (active)

The `exploit` mode dynamically compiles and runs the exploit source code with stdio interactions inside the program.
It can catch interrupts from short-stopped attempts as well

### input mode (passive)

```
-i <uname -a output>
```

The `input` mode allows you to perform enumeration with just the output of a `uname -a` command, 
which makes it useful as a host-side only enumeration tool.

### digestible ouput

```
--digest json
```

This option allows you to dump the results of a kernelpop run to a digestible json file for later processing. So
far, I have just implemented the `json` dump, but I will work on an XML version if it is requested.

### Process for adding kernel vulnerability windows: [ should write a scraper ]

* google: CVE-XXXX-XXXX "ubuntu"

    * click the canonical link (https://people.canonical.com/~ubuntu-security/cve/2016/CVE-XXXX-XXXX.html)

        * click all linked advisories at usn.ubuntu.com and parse info

        * grab patch versions for filling in vulnerability windows per version

* google: CVE-XXXX-XXXX "debian"

    * security-tracker.debian.org link (https://security-tracker.debian.org/tracker/CVE-XXXX-XXXX)

        * pull information from the bottom of the page that relates to the patched versions for the specific cve

* google: CVE-XXXX-XXXX "mitre"

    * links to other distros to pull info from

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

* `CVE-2014-0038`

* `CVE-2013-2094`

* `CVE-2010-4347`

* `CVE-2010-2959`

* `CVE-2009-1185`

---

### exploit sources

`https://github.com/SecWiki/linux-kernel-exploits`

`http://exploit-db.com/`

`https://github.com/lucyoa/kernel-exploits`

`https://github.com/SecWiki/windows-kernel-exploits`

### historical distro sources

Debian

* [debian releases](http://cdimage.debian.org/cdimage/archive/)


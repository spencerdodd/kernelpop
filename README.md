# kernelpop

kernelpop is a framework for performing automated kernel exploitation on Windows, Linux, and Mac hosts.

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
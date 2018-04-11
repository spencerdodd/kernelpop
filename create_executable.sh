#!/bin/bash

echo "[*] creating an executable of the project"

echo "[*] identifying build environment"
if [[ $(uname -a) = *"Darwin"* ]]; then
	echo "	[+] running on mac"
	echo "[*] installing pip"
	sudo easy_install pip || echo "[!] could not install pip"
else
	echo "	[+] running on linux"
	echo "[*] installing pip"
	sudo apt-get install python-pip || echo "[!] could not install pip"
fi

echo "[*] installing pyinstaller"
pip install pyinstaller || echo "[!] could not install pyinstaller"


echo "[*] building the executable"
pyinstaller kernelpop.py --onefile

echo "[*] copying executable to project root"
cp dist/kernelpop .

echo "[*] cleaning up build"
rm -r $(pwd)/build $(pwd)/dist $(pwd)/kernelpop.spec

executable_location="$(pwd)/kernelpop"
echo "[+] executable at $executable_location"
echo "[+] complete"

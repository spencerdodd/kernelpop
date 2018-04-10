#!/bin/bash

echo "[*] creating an executable of the project"

single_file="$(pwd)/singlefile.py"
echo "[*] compiling project into single file at $single_file"
dirs=('exploits' 'exploits/linux' 'exploits/mac' 'exploits/windows' 'src' 'constants.py' 'kernelpop.py')
echo "" > $single_file
for dir in ${dirs[@]}; do
    current_find_dir="$dir"
    echo "[*] searching in $dir"
    for file in $(find $(pwd)/$dir -name '*.py'); do
        cat $file >> $single_file
        echo "" >> $single_file
    done
done

echo "[*] building the executable"
pyinstaller singlefile.py --onefile

echo "[*] copying to project directory"
cp dist/singlefile kernelpop

echo "[*] cleaning up build"
rm -r $(pwd)/build $(pwd)/dist $(pwd)/singlefile.spec

executable_location="$(pwd)/kernelpop"
echo "[+] executable at $executable_location"
echo "[+] complete"

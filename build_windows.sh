#!/bin/bash
echo -e "\033[0;32mHow many CPU cores do you want to be used in compiling process? (Default is 1. Press enter for default.)\033[0m"
read -e CPU_CORES
if [ -z "$CPU_CORES" ]
then
	CPU_CORES=1
fi

# Upgrade the system and install required dependencies
	sudo apt update
	sudo apt install git zip unzip build-essential libtool bsdmainutils autotools-dev autoconf pkg-config automake python3 curl g++-mingw-w64-x86-64 libqt5svg5-dev -y
	echo "1" | sudo update-alternatives --config x86_64-w64-mingw32-g++

# Disable WSL support for Win32 applications.
	sudo bash -c "echo 0 > /proc/sys/fs/binfmt_misc/status"

# Remember path environment variable and strip out any problematic Windows paths
	PATH_OLD=$PATH
	PATH=$(echo "$PATH" | sed -e 's/:\/mnt.*//g')

# Get the root dir of the project where this script should be located
	PROJECT_ROOT=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Compile dependencies
	cd $PROJECT_ROOT/depends
	make -j$(echo $CPU_CORES) HOST=x86_64-w64-mingw32 
	cd ..

# Compile
	./autogen.sh
	./configure --prefix=$PROJECT_ROOT/depends/x86_64-w64-mingw32 --disable-debug --disable-tests --disable-bench --disable-online-rust CFLAGS="-O3" CXXFLAGS="-O3"
	make -j$(echo $CPU_CORES) HOST=x86_64-w64-mingw32
	cd ..

# Create zip file of binaries
	cp $PROJECT_ROOT/src/itcoind.exe $PROJECT_ROOT/src/itcoin-cli.exe $PROJECT_ROOT/src/itcoin-tx.exe $PROJECT_ROOT/src/qt/itcoin-qt.exe .
	zip itcoin-Windows.zip itcoind.exe itcoin-cli.exe itcoin-tx.exe itcoin-qt.exe
	rm -f itcoind.exe itcoin-cli.exe itcoin-tx.exe itcoin-qt.exe

# Restore original path environment variable
	PATH=$PATH_OLD

# Enable WSL support for Win32 applications.
	sudo bash -c "echo 1 > /proc/sys/fs/binfmt_misc/status"

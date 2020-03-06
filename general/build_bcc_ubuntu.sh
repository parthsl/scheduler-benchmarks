#! /bin/bash

ubuntu_ver="`cat /etc/os-release | grep "VERSION="`"

if [[ $ubuntu_ver == *"18.04"* ]]; then
	sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
	  libllvm6.0 llvm-6.0-dev libclang-6.0-dev python zlib1g-dev libelf-dev
else
	if [[ $ubuntu_ver = *"19.10"* ]]; then
		sudo apt install -y bison build-essential cmake flex git libedit-dev \
		  libllvm7 llvm-7-dev libclang-7-dev python zlib1g-dev libelf-dev
	else
		sudo apt-get -y install bison build-essential cmake flex git libedit-dev \
		  libllvm3.7 llvm-3.7-dev libclang-3.7-dev python zlib1g-dev libelf-dev
	fi
fi

git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd

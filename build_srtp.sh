#!/usr/bin/env bash
cd libraries/srtp
if [[ -d build ]]; then
	sudo rm -r build
fi
mkdir build && cd build
../configure
if [[ $? -ne 0 ]]; then
	echo "Configure failed"
	exit 1
fi
make -j 12
sudo make install

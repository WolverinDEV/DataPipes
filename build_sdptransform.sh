#!/usr/bin/env bash

cd libraries/sdptransform/
if [ -d build ]; then
	sudo rm -r build
fi
mkdir build && cd build
cmake .. -DCMAKE_CXX_FLAGS="-fPIC"
if [ $? -ne 0 ]; then
	echo "failed to generate cmake project!"
	exit 1
fi
make -j 12
if [ $? -ne 0 ]; then
	echo "failed to build!"
	exit 1
fi
sudo make install

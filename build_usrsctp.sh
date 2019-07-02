#!/usr/bin/env bash
cd libraries/usrsctp/
if [ -d build ]; then
	sudo rm -r build
fi
mkdir build && cd build

gcc_version=$(gcc -v 2>&1 | sed -n -E 's:^gcc version ([0-9]+)\.(.*):\1:p')
_cflags=""
[[ ${gcc_version} -ge 9 ]] && _cflags="${_cflags} -Wno-error=format-truncation= -Wno-error=address-of-packed-member"
cmake .. -DCMAKE_C_FLAGS="-fPIC $_cflags" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
if [[ $? -ne 0 ]]; then
	echo "failed to generate cmake project!"
	exit 1
fi
make -j 12
if [[ $? -ne 0 ]]; then
	echo "failed to build!"
	exit 1
fi
sudo make install

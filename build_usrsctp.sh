cd libraries/usrsctp/
if [ -d build ]; then
	sudo rm -r build
fi
mkdir build && cd build
cmake .. -DCMAKE_C_FLAGS="-fPIC -Wno-error=format-truncation= -Wno-error=address-of-packed-member" -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE:-Release}"
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

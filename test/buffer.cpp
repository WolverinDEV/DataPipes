#include <iostream>
#include <cmath>
#include <iomanip>
#include <bitset>
#include <cstring>
#include <chrono>
#include <pipes/buffer.h>

using namespace std;
using namespace std::chrono;
using namespace pipes;

void test_buffer_view() {
	/* local stack allocated buffer view */
	{
		char local_buffer[12] = "Hello World";
		pipes::buffer_view buffer{local_buffer, 12};
		assert(!buffer.owns_buffer());
		assert(!buffer.empty());
		assert(buffer.length() == 12);
		assert(!!buffer);

		assert(buffer.data_ptr<char>() == local_buffer);
		auto _world_buffer = buffer.view(6);
		assert(_world_buffer.view(0, 5).string() == "World");
		assert(_world_buffer[5] == 0);
		assert(_world_buffer.length() == 6);
		assert(!_world_buffer.owns_buffer());
	}
	/* heap allocated buffer */
	{
		char local_buffer[12] = "Hello World";
		pipes::buffer buffer{local_buffer, 12};
		assert(buffer.owns_buffer());
		assert(!buffer.empty());
		assert(buffer.length() == 12);
		assert(!!buffer);

		assert(buffer.data_ptr<char>() != local_buffer);
		auto _world_buffer = buffer.range(6);
		assert(_world_buffer.view(0, 5).string() == "World");
		assert(_world_buffer[5] == 0);
		assert(_world_buffer.length() == 6);
		assert(_world_buffer.owns_buffer());

		auto _view_buffer = pipes::buffer_view{buffer};
		assert(_view_buffer.owns_buffer());
		assert(!_view_buffer.empty());
		assert(_view_buffer.length() == 12);
		assert(!!_view_buffer);
		auto _tmp = _view_buffer.view(6);
		_view_buffer = _tmp;

		/* reset direct buffer accessors */
		buffer = pipes::buffer{};
		_world_buffer = pipes::buffer{};
		assert(buffer.data_ptr<char>() == nullptr);
		assert(_world_buffer.data_ptr<char>() == nullptr);

		/* not the _view_buffer should still hold the pointer. Test it */
		{
			assert(_view_buffer.view(0, 5).string() == "World");
			assert(_view_buffer[5] == 0);
			assert(_view_buffer.length() == 6);
			assert(_view_buffer.owns_buffer());
		}
	}
}

int main(int, char**) {
	test_buffer_view();
	return 0;
}
#include <iostream>
#include <cmath>
#include <iomanip>
#include <bitset>
#include <cstring>
#include <chrono>
#include "include/buffer.h"

using namespace std;
using namespace std::chrono;
using namespace pipes;

#define P_B(buffer) \
cout << (buffer).length() << " - " << (buffer).capacity() << " - " << (buffer).capacity_origin() << endl;

extern uint16_t header_fill_mask_sum(uint8_t mask);
extern std::string header_fill_mask_string(uint8_t mask);
void c(int type) {
	auto& info = pipes::type_info[type];

	cout << "Type " << type << ":" << endl;
	cout << " Block size: " << info->block_size << endl;
	cout << " Header size: " << info->header_size << endl;
	cout << " Header size + Padding: " << info->block_offset << endl;
	cout << " Header block count: " << info->block_count << endl;
	cout << " Header free size " << info->block_offset - info->header_size << endl;
	cout << " Header filled with " << header_fill_mask_string(info->fill_mask) << endl;
	cout << " Header filled bytes " << header_fill_mask_sum(info->fill_mask) << endl;
	/*
	auto chunk_size = pow(2, type + 4);
	auto header_used_bytes =  BLK_SIZE - (floor((BLK_SIZE - header_size) / chunk_size) * chunk_size);

	cout << setw(4) << type << setw(13) << chunk_size << setw(14) << header_size << setw(14) << floor((BLK_SIZE - header_size) / chunk_size) << setw(14) << header_used_bytes << setw(14) << (header_used_bytes - header_size) << setw(14) << ((float) header_size / header_used_bytes) * 100 << "%";
	cout << " => " << std::bitset<8>(header_fill_mask(header_used_bytes - header_size)) << " -> " << header_fill_mask_string(header_fill_mask(header_used_bytes - header_size)) << endl;
	 */
}

void emp() {}

#define LOOPS 1024
int main(int, char**) {
	/*
	{
		buffer_view buffer("Hello World", 12);
	}
	 */
	char raw_buffer[] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '\0'};

	buffer_view view(raw_buffer, strlen(raw_buffer));

	cout << view.length() << " - " << view.empty() << " - " << view.data_ptr() << " = " << (void*) raw_buffer << endl;
/*
	return 0;
	for(int i = 0; i < 9; i++) c(i);

	PagedAllocator* allocator = new PagedAllocator();

	void* ptr_buffer[1024];
	{
		uint64_t sum = 0;
		uint64_t count = 0;
		for(int i = 0; i< LOOPS; i++) {
			auto beg = system_clock::now();
			for(void*& ptr : ptr_buffer)
				ptr = allocator->allocate_type(0);
			for(void*& ptr : ptr_buffer)
				allocator->free(ptr);
			auto time = duration_cast<nanoseconds>(system_clock::now() - beg).count(); //596.607
			sum += time;
			count++;

		}
		cout << "AVG: " << (double) sum / count << endl;
	}
	{
		uint64_t sum = 0;
		uint64_t count = 0;
		for(int i = 0; i< LOOPS; i++) {
			auto beg = system_clock::now();
			for(void*& ptr : ptr_buffer)
				ptr = (char*) malloc(16);
			for(void*& ptr : ptr_buffer)
				free(ptr);
			auto time = duration_cast<nanoseconds>(system_clock::now() - beg).count(); //596.607
			sum += time;
			count++;

		}
		cout << "AVG: " << (double) sum / count << endl;
	}
	cout << allocator->allocate_type(0) << endl;

	return 0;
	//32768 / (2 ** (type + 4)) + type - 1

	{
		buffer buf(128, 0);

		P_B(buf);
		buf.resize(120);
		P_B(buf);
		buf.resize(128);
		P_B(buf);
		buf.resize(130);
		P_B(buf);
		buf.resize(120);
		P_B(buf);

		{
			auto sub = buf.range(2, 2);
			cout << sub.length() << endl;
			sub[0] = 1;
			cout << sub.at<uint8_t, int>(0) << endl;
		}
		cout << " - " << endl;
		cout << buf.at<uint8_t, int>(0) << endl;
		cout << buf.at<uint8_t, int>(1) << endl;
		cout << buf.at<uint8_t, int>(2) << endl;
		cout << buf.at<uint8_t, int>(3) << endl;
	}
*/
	return 0;
}
/*
Type | Block size | Header size | block count | header used | header free | header usage
   0           16          4097          3839          4112            15       99.6352%
   1           32          2050          1983          2080            30       98.5577%
   2           64          1027          1007          1088            61       94.3934%
   3          128           516           507           640           124        80.625%
   4          256           261           254           512           251       50.9766%
   5          512           134           127           512           378       26.1719%
   6         1024            71            63          1024           953       6.93359%
   7         2048            40            31          2048          2008       1.95312%
   8         4096            25            15          4096          4071      0.610352%

   0           16          2049          1919          2064            15       99.2733%
   1           32          1026           991          1056            30       97.1591%
   2           64           515           503           576            61       89.4097%
   3          128           260           253           384           124       67.7083%
   4          256           133           127           256           123       51.9531%
   5          512            70            63           512           442       13.6719%
   6         1024            39            31          1024           985       3.80859%
   7         2048            24            15          2048          2024       1.17188%
   8         4096            17             7          4096          4079      0.415039%
 */
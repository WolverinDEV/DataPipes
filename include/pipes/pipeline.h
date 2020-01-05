#pragma once

#include "./misc/logger.h"
#include "./buffer.h"
#include <string>
#include <deque>
#include <mutex>
#include <memory>
#include <utility>

#ifndef __attribute_deprecated__
    #ifdef WIN32
        #define __attribute_deprecated__ __declspec(deprecated)
    #else
        #define __attribute_deprecated__
    #endif
#endif

namespace pipes {
	enum ProcessResult {
		PROCESS_RESULT_OK,
		PROCESS_RESULT_ERROR,
		PROCESS_RESULT_NEED_DATA,
		PROCESS_RESULT_INVALID_DATA,
		PROCESS_RESULT_INVALID_STATE
	};

	enum ProcessDirection {
		PROCESS_DIRECTION_IN = 0,
		PROCESS_DIRECTION_OUT = 1,
	};

	namespace impl {
		extern size_t buffer_bytes_available(std::deque<buffer> &queue);
		extern size_t buffer_peek_bytes(std::deque<buffer> &queue, char *result, size_t length);
		extern size_t buffer_read_bytes(std::deque<buffer> &queue, char *result, size_t length);
	}

	template<typename WriteType>
	class Pipeline {
			//fnc := function callback
			typedef std::function<void(const std::string &)> fnc_write_lagacy;
			typedef std::function<void(const buffer_view &)> fnc_write;
			typedef std::function<void(int /* error code */, const std::string & /* additional message */)> fnc_error;
			using cb_data = std::function<void(const WriteType & /* data */)>;

		public:
			explicit Pipeline(std::string name) : _name(std::move(name)) {}

			inline std::string name() { return this->_name; }

			void callback_data(const cb_data &callback) {
				this->_callback_data = callback;
			}

			void callback_write(const fnc_write &callback) {
				this->_callback_write = callback;
			}

			void callback_error(const fnc_error &callback) {
				this->_callback_error = callback;
			}

			/**
			 * @return true if direct processing is enabled
			 */
			bool direct_process(ProcessDirection direction) const {
				if (direction == ProcessDirection::PROCESS_DIRECTION_IN)
					return this->process_direct_in;
				else if (direction == ProcessDirection::PROCESS_DIRECTION_OUT)
					return this->process_direct_out;
				return false;
			}

			/**
			 * Enable/disable direct processing for each directions
			 */
			void direct_process(ProcessDirection direction, bool flag) {
				if (direction == ProcessDirection::PROCESS_DIRECTION_IN)
					this->process_direct_in = flag;
				else if (direction == ProcessDirection::PROCESS_DIRECTION_OUT)
					this->process_direct_out = flag;
			}


			virtual ProcessResult process_incoming_data(const buffer_view &data) {
				{
					std::lock_guard<std::mutex> lock(this->buffer_lock);
					this->read_buffer.push_back(data.own_buffer());
				}

				if (this->process_direct_in)
					this->process_data_in();
				return ProcessResult::PROCESS_RESULT_OK;
			}

			virtual ProcessResult send(const WriteType &data) {
				{
					std::lock_guard<std::mutex> lock(this->buffer_lock);
					this->write_buffer.push_back(data);
				}

				if (this->process_direct_out)
					this->process_data_out();
				return ProcessResult::PROCESS_RESULT_OK;
			}

			/**
			 * @param directions This is a bitmask for the direction
			 * @return
			 */
			virtual ProcessResult process_data(int directions) {
				ProcessResult result = ProcessResult::PROCESS_RESULT_OK;

				if ((directions & ProcessDirection::PROCESS_DIRECTION_IN) > 0)
					result = this->process_data_in();
				if (result > 0) return result;

				if ((directions & ProcessDirection::PROCESS_DIRECTION_OUT) > 0)
					result = this->process_data_out();
				if (result > 0) return result;

				return result;
			}

			std::shared_ptr<pipes::Logger> logger() { return this->_logger; }

			void logger(const std::shared_ptr<pipes::Logger> &logger) { this->_logger = logger; }

			__attribute_deprecated__ void callback_write(const fnc_write_lagacy &callback) { /* for std::string */
				this->_callback_write = [callback](const buffer_view& buffer) {
					callback(buffer.string());
				};
			}
			__attribute_deprecated__ virtual ProcessResult process_incoming_data(const std::string &data) {
				return this->process_incoming_data(buffer((void*) data.data(), data.length()));
			}
		protected:
			virtual ProcessResult process_data_in() = 0;

			virtual ProcessResult process_data_out() = 0;

			std::shared_ptr<pipes::Logger> _logger;
			std::mutex buffer_lock;
			std::deque<buffer> read_buffer;

			inline size_t buffer_read_bytes_available() {
				std::lock_guard<std::mutex> lock(this->buffer_lock);
				return impl::buffer_bytes_available(this->read_buffer);
			}

			inline size_t buffer_read_peek_bytes(char *buffer, size_t length) {
				std::lock_guard<std::mutex> lock(this->buffer_lock);
				return impl::buffer_peek_bytes(this->read_buffer, buffer, length);
			}

			inline size_t buffer_read_read_bytes(char *buffer, size_t length) {
				std::lock_guard<std::mutex> lock(this->buffer_lock);
				return impl::buffer_read_bytes(this->read_buffer, buffer, length);
			}

			std::deque<WriteType> write_buffer;

			std::string _name;

			fnc_error _callback_error = [](int, const std::string &) {};
			cb_data _callback_data = [](const WriteType &) {};
			fnc_write _callback_write;


			bool process_direct_in = false;
			bool process_direct_out = false;
	};
}
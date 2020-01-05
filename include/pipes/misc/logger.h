#pragma once

#include <string>
#include <functional>
#include <cstdarg>

namespace pipes {
	class Logger {
		public:
			enum LogLevel {
				VERBOSE,
				DEBUG,
				INFO,
				ERROR
			};
			typedef void(*cb_log)(LogLevel, const std::string&, const std::string&, ...);

			cb_log callback_log = nullptr;

			template <typename... Args>
			void log(LogLevel level, const std::string& name, const std::string& message, Args&&... args) {
				if(callback_log)
					callback_log(level, name, message, args...);
			}
		private:
	};
}

/* internal use only */
#ifdef DEFINE_LOG_HELPERS
    #define LOG_XXX(logger, type, name, message, ...) \
	do { \
		 auto _logger = (logger);\
		if(_logger) { \
			_logger->log(pipes::Logger::type, name, message, ##__VA_ARGS__); \
		} \
	} while (0)

    #ifndef LOG_LEVEL
        #define LOG_LEVEL 2
    #endif

    #if LOG_LEVEL <= 0
        #define LOG_VERBOSE(logger, name, message, ...) LOG_XXX(logger, VERBOSE, name, message, ##__VA_ARGS__)
    #else
        #define LOG_VERBOSE(logger, name, message, ...)
    #endif

    #if LOG_LEVEL <= 1
        #define LOG_DEBUG(logger, name, message, ...)   LOG_XXX(logger, DEBUG, name, message, ##__VA_ARGS__)
    #else
        #define LOG_DEBUG(logger, name, message, ...)
    #endif

    #if LOG_LEVEL <= 2
        #define LOG_INFO(logger, name, message, ...)    LOG_XXX(logger, INFO, name, message, ##__VA_ARGS__)
    #else
        #define LOG_INFO(logger, name, message, ...)
    #endif

    #if LOG_LEVEL <= 3
        #define LOG_ERROR(logger, name, message, ...)   LOG_XXX(logger, ERROR, name, message, ##__VA_ARGS__)
    #else
        #define LOG_ERROR(logger, name, message, ...)
    #endif
#endif
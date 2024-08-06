#ifndef TEST_DEBUG
#define TEST_DEBUG
#include <stdio.h>

#define TEST_ENABLE 0

#define TEST_ENABLE_2 1

#if TEST_ENABLE == 1
#warning "Test print is enabled: To disable change the TEST_ENABLE flag to 0 in test_debug.h file"
#endif

#if TEST_ENABLE_2 == 1
#warning "Test print of critical point  is enabled: To disable change the TEST_CRITICAL_POINT flag to 0 in test_debug.h file"
#endif


#define TEST_PRINT(...) \
                if(TEST_ENABLE){ \
                    printf(__VA_ARGS__); }\
                else { \
                   }


#define TEST_PRINT_2(...) \
                if(TEST_ENABLE_2){ \
                    printf(__VA_ARGS__); }\
                else { \
                   }

#endif


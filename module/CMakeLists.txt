set(SOURCES
	gmsv_random.cpp)

add_library(gmsv_random SHARED ${SOURCES})
target_link_libraries(gmsv_random gmod-module-base)

set_gmod_suffix_prefix(gmsv_random)

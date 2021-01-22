set(SOURCES
	random.cpp)

add_library(random SHARED ${SOURCES})
target_link_libraries(random gmod-module-base)

set_gmod_suffix_prefix(random)

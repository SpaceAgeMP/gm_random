set(SOURCES
	random.cpp)

add_library(random SHARED ${SOURCES})

target_link_libraries(random gmod-module-base)

if (WIN32)
	target_link_libraries(random bcrypt.lib)
endif (WIN32)

if (APPLE)
	target_link_libraries(random Security)
endif (APPLE)

set_gmod_suffix_prefix(random)

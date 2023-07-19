set(ttd2mdmp_STATIC_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(ttd2mdmp_STATIC_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ttd2mdmp sources
set(ttd2mdmp_SRC
	${ttd2mdmp_STATIC_SRC}/ttd2mdmp_pe.cpp
	${ttd2mdmp_STATIC_SRC}/ttd_utils.cpp
	${ttd2mdmp_STATIC_SRC}/ttd2mdmp.cpp
)

set(ttd2mdmp_INCLUDE
	${ttd2mdmp_STATIC_INCLUDE}/ttd.h
	${ttd2mdmp_STATIC_INCLUDE}/crypto.h
	${ttd2mdmp_STATIC_INCLUDE}/ttd_utils.h
	${ttd2mdmp_STATIC_INCLUDE}/ttd2mdmp_pe.h
)

add_executable(ttd2mdmp ${ttd2mdmp_SRC} ${ttd2mdmp_INCLUDE})
target_include_directories(ttd2mdmp PUBLIC ${ttd2mdmp_STATIC_INCLUDE})

if(MSVC)
	add_definitions(-DWIN32 -DUNICODE -D_UNICODE)
	target_compile_options(ttd2mdmp PUBLIC "$<$<CONFIG:DEBUG>:/MTd>" "$<$<CONFIG:DEBUG>:/WX>")
	target_compile_options(ttd2mdmp PUBLIC "$<$<CONFIG:RELEASE>:/MT>" "$<$<CONFIG:RELEASE>:/WX>")
endif()

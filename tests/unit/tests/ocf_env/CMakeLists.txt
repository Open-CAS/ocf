add_library(ocf_env ocf_env.c /usr/include/sys/types.h /usr/include/setjmp.h /usr/include/cmocka.h)
add_definitions(-Dstatic=  -Dinline=  )
target_link_libraries(ocf_env pthread z)

cmake_minimum_required(VERSION 3.22)
project(enko_scenario_native C)

add_library(scenario_native SHARED scenario_native.c)
find_library(log-lib log)
target_link_libraries(scenario_native ${log-lib})

target_compile_options(scenario_native PRIVATE
    -Wall -Wextra -O2
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fvisibility=hidden
)

target_link_options(scenario_native PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

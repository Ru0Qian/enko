cmake_minimum_required(VERSION 3.22)
project(agpcore C)

# All source files (always compiled)
set(AGPCORE_SRC_FILES
    enko_vmp.c
    enko_jni.c
    enko_aes.c
    enko_gcm.c
    enko_key.c
    enko_anti_dump.c
    enko_integrity.c
    enko_extract.c
    enko_anti_debug.c
)

# Files compiled by NDK (excludes OLLVM-compiled files when OLLVM is ON)
option(ENKO_OLLVM "Enable OLLVM/Hikari obfuscation" OFF)
option(ENKO_OLLVM_REQUIRED "Fail configure when OLLVM is enabled but unavailable" ON)
set(ENKO_OLLVM_CLANG "/opt/enko/toolchains/hikari-llvm19/install/bin/clang" CACHE FILEPATH "Path to Hikari/OLLVM clang")

if(ENKO_OLLVM)
    # Files compiled with Hikari clang (removed from NDK sources).
    # Keep enko_key.c on the NDK path: it contains byte-exact per-APK key
    # slots patched by the packer after compilation, and OLLVM data rewriting
    # can make those patched bytes diverge from the runtime reads.
    set(OLLVM_SRC_FILES
        enko_aes.c
        enko_gcm.c
        enko_anti_dump.c
        enko_integrity.c
        enko_extract.c
        enko_anti_debug.c
    )
    # Base NDK sources = all sources minus OLLVM sources
    set(NDK_SRC_FILES enko_vmp.c enko_jni.c enko_key.c)
else()
    set(NDK_SRC_FILES ${AGPCORE_SRC_FILES})
endif()

add_library(agpcore SHARED ${NDK_SRC_FILES})

target_include_directories(agpcore PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

find_library(log-lib log)

target_link_libraries(agpcore ${log-lib} dl)

target_compile_options(agpcore PRIVATE
    -Wall -Wextra -O2
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -fno-strict-aliasing
    -fvisibility=hidden
    -ffunction-sections -fdata-sections
)

target_link_options(agpcore PRIVATE
    -Wl,--gc-sections
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

# ======================================================================
# OLLVM / Hikari obfuscation
# Enable with: -DENKO_OLLVM=ON
#
# Hybrid approach:
#   - OLLVM-clang  → compile selected .c → .o (with -sub pass)
#   - NDK-clang    → link .o → libagpcore.so
# This isolates the OLLVM codegen from the NDK linker.
#
# Setup:
#   1. Build Hikari-LLVM19 from source
#   2. Install to /opt/enko/toolchains/hikari-llvm19/install/
# ======================================================================

if(ENKO_OLLVM)
    set(OLLVM_CLANG "${ENKO_OLLVM_CLANG}")
    if(NOT EXISTS "${OLLVM_CLANG}")
        if(ENKO_OLLVM_REQUIRED)
            message(FATAL_ERROR "[enko] Hikari/OLLVM clang not found: ${OLLVM_CLANG}. Set -DENKO_OLLVM_CLANG=/path/to/clang or build with -PenkoEnableOllvm=false -PenkoAllowWeakRelease=true.")
        endif()
        message(WARNING "[enko] Hikari/OLLVM clang not found: ${OLLVM_CLANG}; falling back to normal NDK compile")
        set(ENKO_OLLVM OFF)
    endif()
endif()

if(ENKO_OLLVM)

    set(OLLVM_CFLAGS
        --target=${CMAKE_C_COMPILER_TARGET}
        --sysroot=${CMAKE_SYSROOT}
        -O2 -fPIC
        -DANDROID -DNDEBUG -Dagpcore_EXPORTS
        -Wall -Wextra
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fno-strict-aliasing
        -fvisibility=hidden
        -ffunction-sections -fdata-sections
        -mllvm -hikari
        -mllvm -enable-cffobf
        -mllvm -enable-subobf
        -mllvm -enable-bcfobf
        -mllvm -enable-splitobf
        -mllvm -enable-strcry
    )

    foreach(src ${OLLVM_SRC_FILES})
        get_filename_component(base ${src} NAME_WE)
        set(obj "${CMAKE_CURRENT_BINARY_DIR}/ollvm_${base}.o")
        add_custom_command(
            OUTPUT "${obj}"
            COMMAND ${OLLVM_CLANG} ${OLLVM_CFLAGS}
                -I${CMAKE_CURRENT_SOURCE_DIR}
                -c "${CMAKE_CURRENT_SOURCE_DIR}/${src}"
                -o "${obj}"
            DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${src}"
            COMMENT "[enko] Hikari obfuscate: ${src}"
        )
        list(APPEND OLLVM_OBJS "${obj}")
    endforeach()

    add_custom_target(ollvm_objs DEPENDS ${OLLVM_OBJS})
    add_dependencies(agpcore ollvm_objs)

    target_link_options(agpcore PRIVATE ${OLLVM_OBJS})

    message(STATUS "[enko] Hikari enabled: all passes on ${OLLVM_SRC_FILES}")
endif()

if(NOT DEFINED CORE_LIBRARY OR CORE_LIBRARY STREQUAL "")
    message(FATAL_ERROR "CORE_LIBRARY is required")
endif()

find_program(SOLARIS_NM NAMES llvm-nm nm)
if(NOT SOLARIS_NM)
    message(FATAL_ERROR "nm or llvm-nm is required")
endif()

execute_process(
    COMMAND "${SOLARIS_NM}" -D --defined-only "${CORE_LIBRARY}"
    RESULT_VARIABLE nm_result
    OUTPUT_VARIABLE nm_output
    ERROR_VARIABLE nm_error)
if(NOT nm_result EQUAL 0)
    message(FATAL_ERROR "failed to inspect exports: ${nm_error}")
endif()

string(REGEX MATCHALL "(^|\n)[^\n]+" export_lines "${nm_output}")
set(unexpected)
foreach(line IN LISTS export_lines)
    string(STRIP "${line}" line)
    if(line STREQUAL "")
        continue()
    endif()
    string(REGEX REPLACE "^.*[ \t]([^ \t]+)$" "\\1" symbol "${line}")
    string(REGEX REPLACE "@@?.*$" "" symbol "${symbol}")
    if(NOT symbol STREQUAL "aproxy_engine_get_api" AND
       NOT symbol MATCHES "^SOLARIS_CORE_")
        list(APPEND unexpected "${symbol}")
    endif()
endforeach()

if(unexpected)
    list(JOIN unexpected ", " unexpected_text)
    message(FATAL_ERROR "unexpected exported symbols: ${unexpected_text}")
endif()

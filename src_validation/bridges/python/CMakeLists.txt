# Python bridge CMake

# Build the C++ shim which drives the Python spacepackets bridge.

# Python discovery: interpreter required for subprocess mode. Development is only required for embedding.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(USLP_VALIDATION_EMBED_PYTHON)
  find_package(Python3 COMPONENTS Development REQUIRED)
endif()

add_library(uslp_validation_python
    src/python_bridge.cpp
)

add_library(uslp::validation::python ALIAS uslp_validation_python)

target_include_directories(uslp_validation_python
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../harness/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(uslp_validation_python PUBLIC cxx_std_23)

# Propagate whether we embed Python or call it via subprocess JSON-RPC.
if(USLP_VALIDATION_EMBED_PYTHON)
    target_compile_definitions(uslp_validation_python PUBLIC USLP_VALIDATION_EMBED_PYTHON)
    target_link_libraries(uslp_validation_python PRIVATE Python3::Python)
else()
    if (NOT Python3_Interpreter_FOUND)
        message(FATAL_ERROR "Python3 interpreter is required for USLP_VALIDATION_WITH_PYTHON when not embedding")
    endif()
    target_compile_definitions(uslp_validation_python PUBLIC USLP_VALIDATION_PY_SUBPROCESS)
endif()

# Link against the core harness types.
target_link_libraries(uslp_validation_python
    PUBLIC
        uslp_validation_core
)

install(
    TARGETS uslp_validation_python
    EXPORT uslp_validationTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
)

# Optionally install the Python runner next to shared data; created in a later step.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/runner/runner.py")
    install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/runner/runner.py
            DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/uni_ccsds_validation/python)
endif()
include(${CMAKE_SOURCE_DIR}/cmake/cpm.cmake)

CPMAddPackage(
    NAME nlohmann_json
    VERSION 3.11.3
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)

add_library(uslp_validation_core
    src/engine.cpp
    src/scenario_loader.cpp
    src/metrics_writer.cpp
)

add_library(uslp::validation::core ALIAS uslp_validation_core)

target_include_directories(uslp_validation_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

# Allow core to include bridge headers (compile-time only; linking is done by CLI)
if(USLP_VALIDATION_WITH_PYTHON)
    target_include_directories(uslp_validation_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../bridges/python/include)
endif()
if(USLP_VALIDATION_WITH_NASA)
    target_include_directories(uslp_validation_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../bridges/nasa/include)
endif()

target_link_libraries(uslp_validation_core
    PUBLIC
        nlohmann_json::nlohmann_json
        uni_ccsds
)

target_compile_features(uslp_validation_core PUBLIC cxx_std_23)

# Provide absolute project root to the engine for resolving runner/scripts at runtime
target_compile_definitions(uslp_validation_core
    PRIVATE
        USLP_VALIDATION_PROJECT_ROOT="${CMAKE_SOURCE_DIR}"
)

if(USLP_VALIDATION_WITH_PYTHON)
    target_compile_definitions(uslp_validation_core PUBLIC USLP_VALIDATION_WITH_PYTHON)
endif()

if(USLP_VALIDATION_WITH_NASA)
    target_compile_definitions(uslp_validation_core PUBLIC USLP_VALIDATION_WITH_NASA)
endif()

if(USLP_VALIDATION_ENABLE_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()

install(
    TARGETS uslp_validation_core
    EXPORT uslp_validationTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
)
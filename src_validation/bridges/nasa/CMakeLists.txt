# NASA bridge scaffolding CMake

find_package(Threads REQUIRED)

add_library(uslp_validation_nasa
    src/nasa_bridge.cpp
)

add_library(uslp::validation::nasa ALIAS uslp_validation_nasa)

target_include_directories(uslp_validation_nasa
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        # Also expose the harness public headers so the bridge can include Scenario types
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../harness/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(uslp_validation_nasa PUBLIC cxx_std_23)

# Enable capture-mode macro for future patched NASA sources (harmless for the stub)
target_compile_definitions(uslp_validation_nasa PUBLIC USLP_VALIDATION_CAPTURE)

# Link against core so shared value types (Scenario, etc.) are available to the bridge
target_link_libraries(uslp_validation_nasa
    PUBLIC
        uslp_validation_core
    PRIVATE
        Threads::Threads
)
install(
    TARGETS uslp_validation_nasa
    EXPORT uslp_validationTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION include
)
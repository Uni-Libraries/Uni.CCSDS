add_executable(uslp-validate
    src/main.cpp
)

add_executable(uslp::validate ALIAS uslp-validate)

target_link_libraries(uslp-validate
    PRIVATE
        uslp_validation_core
)

# Link optional bridges so Engine symbols resolve
if(USLP_VALIDATION_WITH_PYTHON)
    target_link_libraries(uslp-validate PRIVATE uslp_validation_python)
endif()

if(USLP_VALIDATION_WITH_NASA)
    target_link_libraries(uslp-validate PRIVATE uslp_validation_nasa)
endif()

target_compile_features(uslp-validate PRIVATE cxx_std_23)

install(
    TARGETS uslp-validate
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
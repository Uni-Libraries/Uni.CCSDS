add_executable(uni_ccsds_cli tool_cli.c)
target_link_libraries(uni_ccsds_cli PRIVATE uni_ccsds)

add_executable(uni_ccsds_bench tool_bench.c)
target_link_libraries(uni_ccsds_bench PRIVATE uni_ccsds)

install(
    TARGETS 
        uni_ccsds_cli 
        uni_ccsds_bench
    RUNTIME DESTINATION bin
)

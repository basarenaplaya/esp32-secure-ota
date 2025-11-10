idf_component_register(
    SRCS "fimware.cpp"
    INCLUDE_DIRS "." "secrets"
)

target_link_libraries(${COMPONENT_TARGET} "-Wl,--Map=output.map")

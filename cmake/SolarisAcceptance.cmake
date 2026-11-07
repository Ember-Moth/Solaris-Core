# CTest labels expose the M2 acceptance IDs as runnable groups. A pruned build
# labels only tests actually registered in that configuration; absence is not a
# passing result. Behavior and evidence boundaries live in DEVELOPMENT_PLAN.md.
function(solaris_m2_label acceptance_id)
    foreach(test_name IN LISTS ARGN)
        if(TEST "${test_name}")
            set_property(TEST "${test_name}" APPEND PROPERTY LABELS "m2;${acceptance_id}")
        endif()
    endforeach()
endfunction()

solaris_m2_label(M2-C01 config_differential_contract config_full_differential_contract)
solaris_m2_label(M2-C02 config_compile_contract config_bounds_contract config_sdk_contract)
solaris_m2_label(M2-R01 route_contract config_routing_contract route_acceptance_contract)
solaris_m2_label(M2-R02 config_routing_contract config_control_contract runtime_control_contract
    runtime_acceptance_contract route_acceptance_contract)
solaris_m2_label(M2-R03 routed_inbound_contract route_acceptance_contract)
solaris_m2_label(M2-U01 udp_association_contract routed_inbound_contract runtime_protocol_contract
    runtime_advanced_contract runtime_acceptance_contract route_acceptance_contract)
solaris_m2_label(M2-U02 runtime_proxy_contract runtime_control_contract runtime_acceptance_contract
    route_acceptance_contract)
solaris_m2_label(M2-L01 config_modules_contract config_slots_contract config_transactions_contract
    runtime_proxy_contract runtime_acceptance_contract route_acceptance_contract)
solaris_m2_label(M2-L02 config_transactions_contract config_control_contract runtime_proxy_contract
    runtime_control_contract runtime_protocol_contract runtime_advanced_contract runtime_acceptance_contract)
solaris_m2_label(M2-O01 operation_contract engine_hooks_contract config_transactions_contract
    sdk_probe_contract log_contract route_acceptance_contract)
solaris_m2_label(M2-O02 observation_contract observation_admission_contract sdk_observe_contract
    runtime_control_contract config_control_contract)
solaris_m2_label(M2-E01 config_host_contract runtime_proxy_contract runtime_control_contract
    runtime_acceptance_contract installed_consumer)
solaris_m2_label(M2-E02 runtime_protocol_contract runtime_advanced_contract config_compile_contract
    config_sdk_contract installed_consumer)
solaris_m2_label(M2-B01 installed_consumer sdk_exports module_symbols module_linked_symbols
    yaml_private_symbols)

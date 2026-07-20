set_project("Solaris")
set_version("0.1.0")
set_xmakever("3.0.9")

add_rules("mode.debug", "mode.release")

option("enable_tun", {default = true, showmenu = true, description = "Build the lwIP-based TUN inbound"})
option("enable_reality", {default = true, showmenu = true, description = "Require the Solaris REALITY BoringSSL patch"})
option("blake3_simd", {default = true, showmenu = true, description = "Enable official BLAKE3 SIMD backends"})

includes("xmake/packages.lua")

add_requires("solaris-boringssl 922c15f", {system = false})
add_requires("solaris-libuv 1.50.0-solaris", {system = false})
add_requires("solaris-pcre2 10.46-solaris", {system = false})
add_requires("solaris-nghttp2 1.64.0-solaris", {system = false})
add_requires("solaris-llhttp 9.2.1-solaris", {system = false})
if has_config("enable_tun") then
    add_requires("solaris-lwip 2.2.1-solaris", {system = false})
end

local core_sources = {
    "src/address.c",
    "src/buffer.c",
    "src/bufpool.c",
    "src/filemap.c",
    "src/framework/memory.c",
    "src/framework/packet_flow.c",
    "src/framework/packet_session.c",
    "src/framework/packet_udp_relay.c",
    "src/ring.c",
    "src/uot.c",
    "src/vmess_addr.c",
    "src/xudp.c",
    "src/framework/direct_outbound.c",
    "src/framework/block_outbound.c",
    "src/framework/dns.c",
    "src/framework/geoip.c",
    "src/framework/geosite.c",
    "src/framework/inbound.c",
    "src/framework/outbound.c",
    "src/framework/outbound_group.c",
    "src/framework/protocol.c",
    "src/framework/router.c",
    "src/framework/sniffer.c",
    "src/framework/socket_protect.c",
    "src/framework/stream.c",
    "src/framework/transport.c",
    "src/inbound/socks5.c"
}

local protocol_sources = {
    "src/frame.c",
    "src/md5.c",
    "src/padding.c",
    "src/vless_protocol.c",
    "src/vless_encryption.c",
    "src/vless_vision.c",
    "src/tls_uv.c",
    "src/reality.c",
    "src/xhttp_config.c",
    "src/xhttp_client.c",
    "src/xhttp_h1.c",
    "src/xhttp_request.c",
    "src/anytls_outbound.c",
    "src/client.c",
    "src/vless_outbound.c",
    "src/shadowsocks_aead.c",
    "src/shadowsocks_outbound.c"
}

local blake3_base_sources = {
    "third_party/blake3/blake3.c",
    "third_party/blake3/blake3_dispatch.c",
    "third_party/blake3/blake3_portable.c"
}

target("core")
    if is_plat("iphoneos", "macosx") then
        set_kind("static")
        set_policy("build.merge_archive", true)
    else
        set_kind("shared")
    end
    set_basename("core")
    set_languages("c11", "c++17")
    set_optimize("fastest")
    on_config(function (target)
        if target:is_plat("android") then
            local runtimes = get_config("runtimes") or get_config("ndk_cxxstl")
            if runtimes ~= "c++_shared" then
                raise("Android builds must use --runtimes=c++_shared to match the CMake/NDK runtime contract.")
            end
        end
    end)
    add_files("src/library.c", "src/engine.c")
    add_files(core_sources)
    add_files(protocol_sources)
    add_files(blake3_base_sources)
    add_includedirs("include", {public = true})
    add_includedirs("src", "src/framework", "third_party/blake3")
    add_headerfiles("include/(solaris/core.h)")
    add_headerfiles("include/(aproxy/engine.h)")
    add_defines("APROXY_BUILDING_LIBRARY")
    add_packages(
        "solaris-boringssl",
        "solaris-libuv",
        "solaris-pcre2",
        "solaris-nghttp2",
        "solaris-llhttp")

    if not is_plat("windows") then
        add_defines("_POSIX_C_SOURCE=200809L", "_DEFAULT_SOURCE")
    end
    if is_plat("linux") then
        add_links("pthread", "dl")
    elseif is_plat("android") then
        set_runtimes("c++_shared")
        add_links("dl")
    end
    if is_plat("windows") then
        add_links("psapi", "ws2_32")
    end

    if is_plat("android") then
        add_ldflags("-Wl,-z,max-page-size=16384", {force = true})
        add_shflags("-Wl,-z,max-page-size=16384", {force = true})
    end

    if has_config("enable_tun") then
        add_defines("APROXY_ENABLE_TUN=1", {public = true})
        add_files("src/framework/packet_tcp_relay.c", "src/inbound/tun.c")
        add_packages("solaris-lwip")
    end

    if has_config("enable_reality") then
        add_defines("APROXY_REQUIRE_REALITY_PATCH=1")
    end

    if is_plat("windows") then
        add_cxflags("/W4", "/WX", {tools = "cl"})
    else
        add_cxflags("-Wall", "-Wextra", "-Werror", "-pedantic", {tools = {"clang", "gcc"}})
    end

    if has_config("blake3_simd") then
        if is_arch("x86_64", "x64", "amd64") and not is_plat("windows") then
            add_files(
                "third_party/blake3/blake3_sse2_x86-64_unix.S",
                "third_party/blake3/blake3_sse41_x86-64_unix.S",
                "third_party/blake3/blake3_avx2_x86-64_unix.S",
                "third_party/blake3/blake3_avx512_x86-64_unix.S")
            add_defines("BLAKE3_USE_NEON=0")
        elseif is_arch("x86", "i386", "i686") or is_plat("windows") and is_arch("x86_64", "x64", "amd64") then
            add_files("third_party/blake3/blake3_sse2.c", {cxflags = "-msse2", tools = {"clang", "gcc"}})
            add_files("third_party/blake3/blake3_sse41.c", {cxflags = "-msse4.1", tools = {"clang", "gcc"}})
            add_files("third_party/blake3/blake3_avx2.c", {cxflags = "-mavx2", tools = {"clang", "gcc"}})
            add_files("third_party/blake3/blake3_avx512.c", {cxflags = "-mavx512f -mavx512vl", tools = {"clang", "gcc"}})
            add_files("third_party/blake3/blake3_sse2.c", {tools = "cl"})
            add_files("third_party/blake3/blake3_sse41.c", {tools = "cl"})
            add_files("third_party/blake3/blake3_avx2.c", {cxflags = "/arch:AVX2", tools = "cl"})
            add_files("third_party/blake3/blake3_avx512.c", {cxflags = "/arch:AVX512", tools = "cl"})
            add_defines("BLAKE3_USE_NEON=0")
        elseif is_arch("arm64", "aarch64", "arm64-v8a") then
            add_files("third_party/blake3/blake3_neon.c")
            add_defines("BLAKE3_USE_NEON=1", "BLAKE3_NO_SSE2", "BLAKE3_NO_SSE41", "BLAKE3_NO_AVX2", "BLAKE3_NO_AVX512")
        elseif is_arch("armv7", "armeabi-v7a") then
            add_files("third_party/blake3/blake3_neon.c", {cxflags = "-mfpu=neon", tools = {"clang", "gcc"}})
            add_defines("BLAKE3_USE_NEON=1", "BLAKE3_NEON_RUNTIME=1", "BLAKE3_NO_SSE2", "BLAKE3_NO_SSE41", "BLAKE3_NO_AVX2", "BLAKE3_NO_AVX512")
        else
            add_defines("BLAKE3_USE_NEON=0", "BLAKE3_NO_SSE2", "BLAKE3_NO_SSE41", "BLAKE3_NO_AVX2", "BLAKE3_NO_AVX512")
        end
    else
        add_defines("BLAKE3_USE_NEON=0", "BLAKE3_NO_SSE2", "BLAKE3_NO_SSE41", "BLAKE3_NO_AVX2", "BLAKE3_NO_AVX512")
    end

target("minimal_host")
    set_kind("binary")
    set_default(false)
    set_languages("c11")
    add_files("examples/minimal_host.c")
    add_deps("core")

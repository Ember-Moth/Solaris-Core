package("solaris-boringssl")
    set_kind("library")
    set_homepage("https://boringssl.googlesource.com/boringssl")
    set_description("Pinned BoringSSL with the Solaris REALITY client patch")
    add_deps("cmake")
    add_urls("https://boringssl.googlesource.com/boringssl.git")
    add_versions("922c15f", "922c15f36cc75db5af33c46f9ea8934553fb808e")

    on_load(function (package)
        package:add("links", "ssl", "crypto")
    end)

    on_install(function (package)
        import("package.tools.cmake")
        os.vrunv("git", {"apply", path.join(os.projectdir(), "third_party/boringssl-reality.patch")})
        local configs = {
            "-DBUILD_SHARED_LIBS=OFF",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON"
        }
        cmake.build(package, configs, {builddir = "build", targets = {"crypto", "ssl"}})
        os.mkdir(package:installdir("include"))
        os.mkdir(package:installdir("lib"))
        os.cp("include/openssl", package:installdir("include"))
        local crypto = path.join("build", package:is_plat("windows") and "crypto.lib" or "libcrypto.a")
        local ssl = path.join("build", package:is_plat("windows") and "ssl.lib" or "libssl.a")
        if not os.isfile(crypto) then
            crypto = os.files("build/**/libcrypto.a")[1] or os.files("build/**/crypto.lib")[1]
        end
        if not os.isfile(ssl) then
            ssl = os.files("build/**/libssl.a")[1] or os.files("build/**/ssl.lib")[1]
        end
        assert(crypto and ssl, "BoringSSL did not produce crypto and ssl libraries")
        os.cp(crypto, package:installdir("lib"))
        os.cp(ssl, package:installdir("lib"))
    end)

package("solaris-libuv")
    set_kind("library")
    set_homepage("https://github.com/libuv/libuv")
    set_description("Pinned libuv for Solaris Core")
    add_deps("cmake")
    add_urls("https://github.com/libuv/libuv.git")
    add_versions("1.50.0-solaris", "8fb9cb919489a48880680a56efecff6a7dfb4504")

    on_load(function (package)
        package:add("links", "uv_a")
    end)

    on_install(function (package)
        local configs = {
            "-DBUILD_SHARED_LIBS=OFF",
            "-DLIBUV_BUILD_SHARED=OFF",
            "-DLIBUV_BUILD_TESTS=OFF",
            "-DLIBUV_BUILD_BENCH=OFF",
            "-DBUILD_TESTING=OFF"
        }
        local opt = {}
        if package:is_plat("android") then
            opt.cxflags = "-DLLONG_MAX=__LONG_LONG_MAX__"
        end
        import("package.tools.cmake").install(package, configs, opt)
    end)

package("solaris-pcre2")
    set_kind("library")
    set_homepage("https://github.com/PCRE2Project/pcre2")
    set_description("Pinned PCRE2 for Solaris Core")
    add_deps("cmake")
    add_urls("https://github.com/PCRE2Project/pcre2.git")
    add_versions("10.46-solaris", "b2bd4254b379b9d7dc9a3dda060a7e27009ccdff")

    on_load(function (package)
        package:add("links", "pcre2-8")
    end)

    on_install(function (package)
        local configs = {
            "-DBUILD_SHARED_LIBS=OFF",
            "-DBUILD_TESTING=OFF",
            "-DPCRE2_BUILD_PCRE2_8=ON",
            "-DPCRE2_BUILD_PCRE2_16=OFF",
            "-DPCRE2_BUILD_PCRE2_32=OFF",
            "-DPCRE2_BUILD_PCRE2GREP=OFF",
            "-DPCRE2_BUILD_TESTS=OFF",
            "-DPCRE2_STATIC_PIC=ON",
            "-DPCRE2_SUPPORT_LIBBZ2=OFF",
            "-DPCRE2_SUPPORT_LIBZ=OFF",
            "-DPCRE2_SUPPORT_LIBREADLINE=OFF"
        }
        import("package.tools.cmake").install(package, configs)
    end)

package("solaris-nghttp2")
    set_kind("library")
    set_homepage("https://github.com/nghttp2/nghttp2")
    set_description("Pinned nghttp2 for Solaris Core")
    add_deps("cmake")
    add_urls("https://github.com/nghttp2/nghttp2.git")
    add_versions("1.64.0-solaris", "526ff38e0249acbcc4d0e8958c12cdeae9960cfe")

    on_load(function (package)
        package:add("links", "nghttp2")
    end)

    on_install(function (package)
        local configs = {
            "-DBUILD_SHARED_LIBS=OFF",
            "-DBUILD_STATIC_LIBS=ON",
            "-DBUILD_TESTING=OFF",
            "-DENABLE_LIB_ONLY=ON",
            "-DENABLE_APP=OFF",
            "-DENABLE_EXAMPLES=OFF",
            "-DENABLE_HPACK_TOOLS=OFF",
            "-DENABLE_PYTHON_BINDINGS=OFF"
        }
        import("package.tools.cmake").install(package, configs)
    end)

package("solaris-llhttp")
    set_kind("library")
    set_homepage("https://github.com/nodejs/llhttp")
    set_description("Pinned llhttp for Solaris Core")
    add_deps("cmake")
    add_urls("https://github.com/nodejs/llhttp.git")
    add_versions("9.2.1-solaris", "610a87d755f6bae466cd871c2ba97574ccac5483")

    on_load(function (package)
        package:add("links", "llhttp")
    end)

    on_install(function (package)
        local configs = {
            "-DBUILD_SHARED_LIBS=OFF",
            "-DBUILD_STATIC_LIBS=ON",
            "-DBUILD_TESTING=OFF"
        }
        import("package.tools.cmake").install(package, configs)
    end)

package("solaris-lwip")
    set_kind("library")
    set_homepage("https://github.com/lwip-tcpip/lwip")
    set_description("Pinned lwIP core with the Solaris libuv sys_arch port")
    add_deps("solaris-libuv")
    add_urls("https://github.com/lwip-tcpip/lwip.git")
    add_versions("2.2.1-solaris", "77dcd25a72509eb83f72b033d219b1d40cd8eb95")

    on_load(function (package)
        package:add("links", "lwip")
    end)

    on_install(function (package)
        os.mkdir("port")
        os.cp(path.join(os.projectdir(), "cmake/mobile/lwip/arch"), "port")
        os.cp(path.join(os.projectdir(), "cmake/mobile/lwip/lwipopts.h"), "port/lwipopts.h")
        os.cp(path.join(os.projectdir(), "cmake/mobile/lwip/sys_arch.c"), "port/sys_arch.c")
        local libuv = assert(package:dep("solaris-libuv"), "solaris-libuv dependency not found")
        local fetchinfo = assert(libuv:fetch(), "solaris-libuv fetch info not found")
        local libuv_includedirs = table.join(fetchinfo.includedirs or {}, fetchinfo.sysincludedirs or {})
        local libuv_include_lines = {}
        for _, includedir in ipairs(libuv_includedirs) do
            table.insert(libuv_include_lines, "    add_includedirs(" .. string.format("%q", includedir:gsub("\\", "/")) .. ")")
        end
        io.writefile("xmake.lua", ([[
set_project("solaris_lwip")
set_languages("c11")

target("lwip")
    set_kind("static")
    set_optimize("fastest")
    add_includedirs("src/include", "port", {public = true})
%s
    if is_plat("linux") then
        add_defines("_DEFAULT_SOURCE", "_GNU_SOURCE")
    end
    add_headerfiles("src/include/(lwip/**.h)")
    add_headerfiles("src/include/(netif/**.h)")
    add_headerfiles("src/include/(posix/**.h)")
    add_headerfiles("port/(arch/**.h)")
    add_headerfiles("port/(lwipopts.h)")
    add_files("src/core/*.c")
    add_files("src/core/ipv4/*.c")
    add_files("src/core/ipv6/*.c")
    add_files("port/sys_arch.c")
]]):format(table.concat(libuv_include_lines, "\n")))
        import("package.tools.xmake").install(package)
    end)

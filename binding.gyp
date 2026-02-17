{
    "targets": [
        {
            "target_name": "ss_binding",
            "sources": ["src/netlink.c", "src/sock_destroy.c", "src/addon.c"],
            "include_dirs": [],
            "defines": ["NAPI_VERSION=9", "_GNU_SOURCE"],
            "cflags": [
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Wno-unused-parameter",
                "-O2",
                "-U_FORTIFY_SOURCE",
                "-D_FORTIFY_SOURCE=3",
                "-fstack-protector-strong",
                "-Wformat=2",
                "-Werror=format-security",
            ],
            "ldflags": ["-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack"],
            "conditions": [["OS!='linux'", {"defines": ["UNSUPPORTED_PLATFORM"]}]],
        }
    ]
}

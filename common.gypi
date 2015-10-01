{
  "variables": {
    "visibility%": "hidden",         # V8"s visibility setting
    "target_arch%": "ia32",          # set v8"s target architecture
    "host_arch%": "ia32",            # set v8"s host architecture
    "library%": "static_library",    # allow override to "shared_library" for DLL/.so builds
    "uv_library%": "static_library", # allow override to "shared_library" for DLL/.so builds
    "component%": "static_library",  # NB. these names match with what V8 expects
    "msvs_multi_core_compile": "0",  # we do enable multicore compiles, but not using the V8 way
    "gcc_version%": "unknown",
    "node_root_dir%": "",
    "clang%": 1,
    "openssl_fips%": "false",
    "bud_asan%": "false",
    "conditions": [
      ["GENERATOR == 'ninja'", {
        "OBJ_DIR": "<(PRODUCT_DIR)/obj",
      }, {
        "OBJ_DIR": "<(PRODUCT_DIR)/obj.target",
      }],
      ["node_root_dir == ''", {
        "LIBOPENSSL": "<(PRODUCT_DIR)/libopenssl.a",
      }, {
        "LIBOPENSSL": "<(PRODUCT_DIR)/openssl.a",
      }],
    ],
  },

  "target_defaults": {
    "default_configuration": "Release",
    "configurations": {
      "Debug": {
        "defines": [ "DEBUG", "_DEBUG" ],
        "cflags": [ "-g", "-O0", "-fwrapv", "-Wno-parentheses-equality" ],
        "xcode_settings": {
          "GCC_OPTIMIZATION_LEVEL": "0"
        },
      },
      "Release": {
        "defines": [ "NDEBUG" ],
        "cflags": [ "-g" ],
      }
    },

    "xcode_settings": {
      "GCC_VERSION": "com.apple.compilers.llvm.clang.1_0",
      "GCC_WARN_ABOUT_MISSING_NEWLINE": "YES",  # -Wnewline-eof
      "PREBINDING": "NO",                       # No -Wl,-prebind
      "OTHER_CFLAGS": [
        "-fstrict-aliasing",
        "-g",
      ],
      "WARNING_CFLAGS": [
        "-Wall",
        "-Wendif-labels",
        "-W",
        "-Wno-unused-parameter",
        "-Wundeclared-selector",
        "-Wno-parentheses-equality",
      ],
    },
    "conditions": [
      ["target_arch=='ia32'", {
        "xcode_settings": {"ARCHS": ["i386"]},
      }],
      ["target_arch=='x64'", {
        "xcode_settings": {"ARCHS": ["x86_64"]},
      }],
      [ "OS in 'linux freebsd openbsd solaris'", {
        "target_conditions": [
          ["_type=='static_library'", {
            "standalone_static_library": 1, # disable thin archive which needs binutils >= 2.19
          }],
        ],
        "conditions": [
          [ "target_arch=='ia32'", {
            "cflags": [ "-m32" ],
            "ldflags": [ "-m32" ],
          }],
          [ "target_arch=='x64'", {
            "cflags": [ "-m64" ],
            "ldflags": [ "-m64" ],
          }],
        ],
      }],
    ]
  },
}

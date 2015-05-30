{
  "targets": [{
    "target_name": "bud",
    "type": "executable",
    "dependencies": [
      "deps/openssl/openssl.gyp:openssl",
      "deps/uv/uv.gyp:libuv",
      "deps/ringbuffer/ringbuffer.gyp:ringbuffer",
      "deps/parson/parson.gyp:parson",
      "deps/http_parser/http_parser.gyp:http_parser",
    ],
    "include_dirs": [
      "src",
      "include",
      "<(SHARED_INTERMEDIATE_DIR)",
    ],
    "sources": [
      "src/avail.c",
      "src/bio.c",
      "src/bud.c",
      "src/client.c",
      "src/client-common.c",
      "src/common.c",
      "src/config.c",
      "src/error.c",
      "src/http-pool.c",
      "src/ipc.c",
      "src/logger.c",
      "src/master.c",
      "src/ocsp.c",
      "src/server.c",
      "src/sni.c",
      "src/tracing.c",
      "src/worker.c",
      "src/xforward.c",
    ],
    "conditions": [
      # FIPS
      ["fips_dir != 'false'", {
        "defines": [
          "BUD_FIPS_ENABLED=1",
        ],
      }],

      # Platform-specifics
      ["OS in ('freebsd', 'mac', 'solaris')", {
        "dependencies": [
          "bud-dtrace",
        ],
      }],

      ["OS == 'linux'", {
        "defines": [
          "_POSIX_C_SOURCE=200112",
          "_GNU_SOURCE",
        ],
      }],

      ['OS in "linux freebsd"', {
        'ldflags': [
          '-Wl,--whole-archive <(LIBOPENSSL) -Wl,--no-whole-archive',
        ],
      }],

      ['OS in "freebsd"', {
        'ldflags': [
          '-Wl,--export-dynamic',
        ],
      }],
    ]
  }, {
    "target_name": "bud-dtrace",
    "type": "none",
    "conditions": [
      ["OS in ('freebsd', 'mac', 'solaris')", {
        "direct_dependent_settings": {
          "defines": [ "BUD_DTRACE" ],
        },
        "actions": [{
          "action_name": "bud-dtrace",
          "inputs": [
            "src/bud_provider.d",
          ],

          "outputs": [
            "<(SHARED_INTERMEDIATE_DIR)/bud_provider.h",
          ],
          "action": [
            "dtrace",
            "-h",
            "-xnolibs",
            "-s",
            "<@(_inputs)",
            "-o",
            "<@(_outputs)",
          ],
        }],
        "conditions": [
          ["OS != 'mac'", {
            "direct_dependent_settings": {
              "sources": [ "<(SHARED_INTERMEDIATE_DIR)/bud_provider.o" ],
            },
            "actions": [{
              "action_name": "bud-dtrace-obj",
              "inputs": [
                "src/bud_provider.d",
                "<(OBJ_DIR)/bud/src/tracing.o",
              ],
              "outputs": [
                "<(SHARED_INTERMEDIATE_DIR)/bud_provider.o",
              ],
              "action": [
                "dtrace",
                "-G",
                "-xnolibs",
                "-s",
                "<@(_inputs)",
                "-o",
                "<@(_outputs)",
              ],
            }],
          }],
          ["OS == 'freebsd'", {
            "direct_dependent_settings": {
              "libraries": [
                "-lelf",
              ],
            }
          }],
        ],
      }],
    ],
  }]
}

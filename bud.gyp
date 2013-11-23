{
  "targets": [{
    "target_name": "bud",
    "type": "executable",
    "dependencies": [
      "deps/openssl/openssl.gyp:openssl",
      "deps/uv/uv.gyp:libuv",
      "deps/ringbuffer/ringbuffer.gyp:ringbuffer",
      "deps/parson/parson.gyp:parson",
    ],
    "include_dirs": [
      "src",
    ],
    "sources": [
      "src/bio.c",
      "src/bud.c",
      "src/client.c",
      "src/config.c",
      "src/error.c",
      "src/server.c",
    ],
    "configuration": [
      [ 'OS in "linux freebsd openbsd solaris"', {
        'conditions': [
          [ 'target_arch=="ia32"', {
            'cflags': [ '-m32' ],
            'ldflags': [ '-m32' ],
          }],
          [ 'target_arch=="x64"', {
            'cflags': [ '-m64' ],
            'ldflags': [ '-m64' ],
          }],
        ],
      }],
    ]
  }]
}

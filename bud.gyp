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
      "src/bud.c",
      "src/config.c",
    ],
  }]
}

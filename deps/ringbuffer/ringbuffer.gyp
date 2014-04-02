{
  "targets": [{
    "target_name": "ringbuffer",
    "type": "<(library)",
    "direct_dependent_settings": {
      "include_dirs": [ "." ],
    },
    "sources": [
      "ringbuffer.c",
    ],
  }, {
    "target_name": "test",
    "type": "executable",
    "dependencies": [ "ringbuffer" ],
    "sources": [ "test.c" ],
  }]
}

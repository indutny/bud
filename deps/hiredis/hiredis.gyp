{
  "targets": [{
    "target_name": "hiredis",
    "type": "<(library)",
    "direct_dependent_settings": {
      "include_dirs": [ "." ],
    },
    "cflags": [ "-std=c99" ],
    "sources": [
      "hiredis/async.c",
      "hiredis/dict.c",
      "hiredis/hiredis.c",
      "hiredis/net.c",
      "hiredis/sds.c",
    ],
  }]
}

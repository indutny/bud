{
  # NOTE: BIG FAT HACK FOR NODE-GYP
  "variables": {
    "library": "static_library",
  },

  "target_defaults": {
    "type": "static_library",
    "include_dirs": [
      "deps/uv/include",
      "deps/openssl/openssl/include",
    ]
  }
}

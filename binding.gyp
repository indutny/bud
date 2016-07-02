{
  "target_defaults": {
    "type": "loadable_module",
    "product_prefix": "",
    "product_extension": "bud",

    "include_dirs": [
      "include/",
      "deps/openssl/openssl/include",
    ],
    "conditions": [
      [ 'OS=="mac"', {
        'defines': [ '_DARWIN_USE_64_BIT_INODE=1' ],
        'libraries': [ '-undefined dynamic_lookup' ],
        'xcode_settings': {
          'DYLIB_INSTALL_NAME_BASE': '@rpath'
        },
      }],
      [ 'OS=="freebsd" or OS=="openbsd" or OS=="solaris" or (OS=="linux" and target_arch!="ia32")', {
        'cflags': [ '-fPIC' ],
      }]
    ]
  }
}

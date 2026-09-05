{
  "targets": [
    {
      "target_name": "mlock_addon",
      "sources": [ "mlock-addon.cc" ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")"
      ],
      "defines": [ "NAPI_DISABLE_CPP_EXCEPTIONS", "NAPI_VERSION=8" ],
      "cflags!": [ "-fno-exceptions" ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "conditions": [
        ["OS=='linux'", {
          "cflags_cc": [ "-std=c++17" ]
        }]
      ]
    }
  ]
}

# SourceMod REST in Pawn Extension
[![Build](https://github.com/eldoradoel/sm-ripext-websocket/actions/workflows/main.yml/badge.svg)](https://github.com/eldoradoel/sm-ripext-websocket/actions/workflows/main.yml)

HTTP Module Project address [https://github.com/ErikMinekus/sm-ripext](https://github.com/ErikMinekus/sm-ripext)

WEBSOCKET Module Project address [https://github.com/Dreae/SourceMod-Websockets](https://github.com/Dreae/SourceMod-Websockets)

HTTP supports setting proxy, support proxy mode details in the http.inc header file

Responses to WEBSOCKET and HTTP support both JSON and raw strings, and more types may be supported in the future 

# Library update
### update libuv to [v1.44.2]

### update libcurl to [v7.84.0]

### update libnghttp2 to [v1.49.0]

### update zlib to [v1.2.12]

### update boost to [1.75.0]

### use openssl to replace mbedtls to solve response data limit to 16384 character.

# Existing problems

In linux and windows, there is a serious performance problem of http/2, which is reflected in the high cpu usage of csgo main thread when requesting. In linux, the whole request process can be completed completely, but in windows, there is a serious problem of buffer reading rate. http/1.1 is currently enforced on windows to circumvent performance issues.

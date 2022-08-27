# SourceMod REST in Pawn Extension
[![Build](https://github.com/eldoradoel/sm-ripext-websocket/actions/workflows/main.yml/badge.svg)](https://github.com/eldoradoel/sm-ripext-websocket/actions/workflows/main.yml)

HTTP模块项目地址 [https://github.com/ErikMinekus/sm-ripext](https://github.com/ErikMinekus/sm-ripext)


WEBSOCKET模块项目地址 [https://github.com/Dreae/SourceMod-Websockets](https://github.com/Dreae/SourceMod-Websockets)

HTTP支持设置代理，支持代理方式详情在http.inc头文件

对WEBSOCKET和HTTP的response支持获取JSON和原始字符串两种方式

# Library update
update libuv to [v1.44.2]

update libcurl to [v7.84.0]

update libnghttp2 to [v1.49.0]

update zlib to [v1.2.12]

update boost to [1.75.0]

use openssl to replace mbedtls to solve response data limit to 16384 character.
# Existing problems

on windows, force use http/1.1, beacuse http/2 on windows have recv speed issue. Everyting works fine on Linux.

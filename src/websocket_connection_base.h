#pragma once
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio.hpp>
#include <memory>
#include "extension.h"
#include <map>

#if defined WIN32
#include <sdkddkver.h>
#endif

namespace websocket = boost::beast::websocket;
namespace beast = boost::beast;
using tcp = boost::asio::ip::tcp;

class websocket_connection_base {
public:
    websocket_connection_base(std::string address, std::string endpoint, uint16_t port);
    void set_write_callback(std::function<void(std::size_t)> callback);
    void set_read_callback(std::function<void(uint8_t *, std::size_t)> callback);
    void set_connect_callback(std::function<void()> callback);
    void set_disconnect_callback(std::function<void()> callback);
    void set_header(std::string key, std::string value);
    void add_headers(websocket::request_type& req);
    void destroy();

    virtual void close() = 0;
    virtual void connect() = 0;
    virtual void write(boost::asio::const_buffer buffer) = 0;

protected:
    std::unique_ptr<std::function<void(uint8_t *, std::size_t)>> read_callback;
    std::unique_ptr<std::function<void(std::size_t)>> write_callback;
    std::unique_ptr<std::function<void()>> connect_callback;
    std::unique_ptr<std::function<void()>> disconnect_callback;
    std::map<std::string, std::string> headers;
    std::mutex header_mutex;
    beast::flat_buffer buffer;
    std::string address;
    std::string endpoint;
    uint16_t port;
    bool pending_delete = false;
};
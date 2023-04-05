#include "websocket_connection_base.h"

websocket_connection_base::websocket_connection_base(std::string address, std::string endpoint, uint16_t port)
{
    this->address = address;
    this->endpoint = endpoint;
    this->port = port;
}

void websocket_connection_base::set_write_callback(std::function<void(size_t)> callback)
{
    this->write_callback = std::make_unique<std::function<void(size_t)>>(callback);
}

void websocket_connection_base::set_read_callback(std::function<void(uint8_t *, size_t)> callback)
{
    this->read_callback = std::make_unique<std::function<void(uint8_t *, size_t)>>(callback);
}

void websocket_connection_base::set_connect_callback(std::function<void()> callback)
{
    this->connect_callback = std::make_unique<std::function<void()>>(callback);
}

void websocket_connection_base::set_disconnect_callback(std::function<void()> callback)
{
    this->disconnect_callback = std::make_unique<std::function<void()>>(callback);
}

void websocket_connection_base::set_header(std::string header, std::string value)
{
    std::lock_guard<std::mutex> guard(this->header_mutex);
    this->headers.insert_or_assign(header, value);
}

void websocket_connection_base::add_headers(websocket::request_type &req)
{
    req.set(beast::http::field::user_agent, std::string(BOOST_BEAST_VERSION_STRING) + " SourceMod-WebSockets v" + SMEXT_CONF_VERSION);
    std::lock_guard<std::mutex> guard(this->header_mutex);
    for (std::pair<std::string, std::string> elem : this->headers)
    {
        req.set(elem.first, elem.second);
    }
}

void websocket_connection_base::destroy()
{
    this->pending_delete = true;
    this->close();
}

bool websocket_connection_base::ws_open()
{
    return this->ws_connect;
}
#include "websocket_connection.h"
#include "websocket_eventloop.h"
#include <boost/asio/strand.hpp>

websocket_connection::websocket_connection(std::string address, std::string endpoint, uint16_t port) : websocket_connection_base(address, endpoint, port)
{
    this->ws = std::make_unique<websocket::stream<beast::tcp_stream>>(boost::asio::make_strand(event_loop.get_context()));
    this->work = std::make_unique<boost::asio::io_context::work>(event_loop.get_context());
    this->resolver = std::make_shared<tcp::resolver>(event_loop.get_context());
}

void websocket_connection::connect()
{
    char s_port[8];
    std::snprintf(s_port, sizeof(s_port), "%hu", this->port);
    tcp::resolver::query query(this->address.c_str(), s_port);

    this->resolver->async_resolve(query, beast::bind_front_handler(&websocket_connection::on_resolve, this));
    g_RipExt.LogMessage("Init Connect %s:%d", address.c_str(), this->port);
}

void websocket_connection::on_resolve(beast::error_code ec, tcp::resolver::results_type results)
{
    if (ec)
    {
        g_RipExt.LogError("Error resolving %s: %d %s", this->address.c_str(), ec.value(), ec.message().c_str());
        if (this->disconnect_callback)
        {
            this->disconnect_callback->operator()();
        }
        this->ws_connect = false;
        return;
    }

    beast::get_lowest_layer(*this->ws).expires_after(std::chrono::seconds(30));
    beast::get_lowest_layer(*this->ws).async_connect(results, beast::bind_front_handler(&websocket_connection::on_connect, this));
}

void websocket_connection::on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type ep)
{
    if (ec)
    {
        g_RipExt.LogError("Error connecting to %s: %d %s", this->address.c_str(), ec.value(), ec.message().c_str());
        if (this->disconnect_callback)
        {
            this->disconnect_callback->operator()();
        }
        this->ws_connect = false;
        return;
    }
    beast::get_lowest_layer(*this->ws).expires_never();

    auto timeout = websocket::stream_base::timeout::suggested(beast::role_type::client);
    timeout.keep_alive_pings = true;
    this->ws->set_option(websocket::stream_base::decorator([this](websocket::request_type &req)
                                                           { this->add_headers(req); }));

    this->ws->async_handshake(this->address, this->endpoint.c_str(), beast::bind_front_handler(&websocket_connection::on_handshake, this));
}

void websocket_connection::on_handshake(beast::error_code ec)
{
    if (ec)
    {
        g_RipExt.LogError("WebSocket Handshake Error: %d %s", ec.value(), ec.message().c_str());
        if (this->disconnect_callback)
        {
            this->disconnect_callback->operator()();
        }
        this->ws_connect = false;
        return;
    }

    this->buffer.clear();
    if (this->connect_callback)
    {
        this->connect_callback->operator()();
    }

    this->ws->async_read(this->buffer, beast::bind_front_handler(&websocket_connection::on_read, this));
    this->ws_connect = true;
    g_RipExt.LogMessage("On Handshaked %s:%d", address.c_str(), this->port);
}

void websocket_connection::on_write(beast::error_code ec, size_t bytes_transferred)
{
    if (ec)
    {
        g_RipExt.LogError("WebSocket write error: %d %s", ec.value(), ec.message().c_str());
        return;
    }
}

void websocket_connection::on_read(beast::error_code ec, size_t bytes_transferred)
{
    if (ec)
    {
        if (this->pending_delete)
        {
            delete this;
        }
        else
        {
            g_RipExt.LogError("WebSocket read error: %d %s", ec.value(), ec.message().c_str());
            if (this->disconnect_callback)
            {
                this->disconnect_callback->operator()();
            }
            this->ws_connect = false;
        }
        return;
    }

    if (this->read_callback)
    {
        auto buffer = reinterpret_cast<uint8_t *>(malloc(bytes_transferred));
        memcpy(buffer, reinterpret_cast<const uint8_t *>(this->buffer.data().data()), bytes_transferred);

        this->read_callback->operator()(buffer, bytes_transferred);
    }
    this->buffer.consume(bytes_transferred);

    this->ws->async_read(this->buffer, beast::bind_front_handler(&websocket_connection::on_read, this));
}

void websocket_connection::on_close(beast::error_code ec)
{
    if (ec)
    {
        g_RipExt.LogError("WebSocket close error: %d %s", ec.value(), ec.message().c_str());
        if (this->pending_delete)
        {
            delete this;
        }
    }
    this->ws_connect = false;
}

void websocket_connection::write(boost::asio::const_buffer buffer)
{
    this->ws->async_write(buffer, beast::bind_front_handler(&websocket_connection::on_write, this));
}

void websocket_connection::close()
{
    this->ws->async_close(websocket::close_code::normal, beast::bind_front_handler(&websocket_connection::on_close, this));
}

bool websocket_connection::socket_open()
{
    return this->ws->is_open();
}
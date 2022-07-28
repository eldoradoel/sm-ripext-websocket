typedef WebSocket_ReadCallback = function void (WebSocket ws, JSON message, any data);
typedef WebSocket_ConnectCallback = function void (WebSocket ws, any data);

enum WebSocket_Protocol {
    WebSocket_JSON
}

methodmap WebSocket < Handle {
    public native void SetHeader(const char[] header, const char[] value);
    public native void Connect();
    public native void Close();
    public native void SetReadCallback(WebSocket_Protocol protocol, WebSocket_ReadCallback callback, any data=0);
    public native void SetConnectCallback(WebSocket_ConnectCallback callback, any data=0);
    public native void SetDisconnectCallback(WebSocket_ConnectCallback callback, any data=0);
    public native void Write(JSON json);
}

native WebSocket WebSocket_Create(const char[] address, const char[] path, int port=80);
native WebSocket WebSocket_CreateSSL(const char[] address, const char[] path, int port=443);
native WebSocket WebSocket_FromURL(const char[] url);
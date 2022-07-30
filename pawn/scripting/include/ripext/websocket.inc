typedef WebSocket_ReadCallback = function void (WebSocket ws, JSON message, any data);
typedef WebSocket_ConnectCallback = function void (WebSocket ws, any data);

enum WebSocket_Protocol {
    WebSocket_JSON
}

methodmap WebSocket < Handle {

	// Creates an WebSocket request.
	//
	// The Handle must be freed via delete or CloseHandle().
	//
	// @param url        URL to the Websocket endpoint Such as [scheme]://[hostname]:[port]?[QueryParam1]&[QueryParam2].
    //                   [scheme] Support ws or wss
    //                   [hostname] Support Domain or IP                    
    //                   For example ws://[hostname]:[port]?test1=1&test2=2 Or wss://[hostname]:[port]?test1=1&test2=2
    public native WebSocket(const char[] url);
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
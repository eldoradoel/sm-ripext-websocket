/**
 * vim: set ts=4 :
 * =============================================================================
 * SourceMod REST in Pawn Extension
 * Copyright 2017-2022 Erik Minekus
 * =============================================================================
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "extension.h"
#include "httprequest.h"

static HTTPRequest *GetRequestFromHandle(IPluginContext *pContext, Handle_t hndl)
{
	HandleError err;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	HTTPRequest *request;
	if ((err = handlesys->ReadHandle(hndl, htHTTPRequest, &sec, (void **)&request)) != HandleError_None)
	{
		pContext->ReportError("Invalid HTTPRequest handle %x (error %d)", hndl, err);
		return nullptr;
	}

	return request;
}

static json_t *GetJSONFromHandle(IPluginContext *pContext, Handle_t hndl)
{
	HandleError err;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	json_t *json;
	if ((err = handlesys->ReadHandle(hndl, htJSON, &sec, (void **)&json)) != HandleError_None)
	{
		pContext->ReportError("Invalid JSON handle %x (error %d)", hndl, err);
		return nullptr;
	}

	return json;
}

static cell_t CreateRequest(IPluginContext *pContext, const cell_t *params)
{
	char *url;
	pContext->LocalToString(params[1], &url);

	if (url[0] == '\0')
	{
		pContext->ReportError("URL cannot be empty.");
		return BAD_HANDLE;
	}

	HTTPRequest *request = new HTTPRequest(url);

	HandleError err;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());
	Handle_t hndlRequest = handlesys->CreateHandleEx(htHTTPRequest, request, &sec, nullptr, &err);
	if (hndlRequest == BAD_HANDLE)
	{
		delete request;

		pContext->ReportError("Could not create HTTPRequest handle (error %d)", err);
		return BAD_HANDLE;
	}

	return hndlRequest;
}

static cell_t AppendRequestFormParam(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	char *name;
	pContext->LocalToString(params[2], &name);

	if (name[0] == '\0')
	{
		pContext->ReportError("Parameter name cannot be empty.");
		return 0;
	}

	char value[8192];
	{
		DetectExceptions eh(pContext);
		smutils->FormatString(value, sizeof(value), pContext, params, 3);

		if (eh.HasException())
		{
			return 0;
		}
	}

	request->AppendFormParam(name, value);

	return 1;
}

static cell_t AppendRequestQueryParam(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	char *name;
	pContext->LocalToString(params[2], &name);

	if (name[0] == '\0')
	{
		pContext->ReportError("Parameter name cannot be empty.");
		return 0;
	}

	char value[8192];
	{
		DetectExceptions eh(pContext);
		smutils->FormatString(value, sizeof(value), pContext, params, 3);

		if (eh.HasException())
		{
			return 0;
		}
	}

	request->AppendQueryParam(name, value);

	return 1;
}

static cell_t SetRequestBasicAuth(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	char *username;
	pContext->LocalToString(params[2], &username);

	char *password;
	pContext->LocalToString(params[3], &password);

	request->SetBasicAuth(username, password);

	return 1;
}

static cell_t SetRequestHeader(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	char *name;
	pContext->LocalToString(params[2], &name);

	if (name[0] == '\0')
	{
		pContext->ReportError("Header name cannot be empty.");
		return 0;
	}

	char value[8192];
	{
		DetectExceptions eh(pContext);
		smutils->FormatString(value, sizeof(value), pContext, params, 3);

		if (eh.HasException())
		{
			return 0;
		}
	}

	request->SetHeader(name, value);

	return 1;
}

static cell_t SetProxy(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	char *proxy;
	pContext->LocalToString(params[2], &proxy);

	if (proxy[0] == '\0')
	{
		pContext->ReportError("Proxy Url cannot be empty.");
		return 0;
	}

	request->SetProxy(proxy);

	return 1;
}

static cell_t PerformGetRequest(IPluginContext *pContext, const cell_t *params)
{
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	IPluginFunction *callback = pContext->GetFunctionById(params[2]);
	cell_t value = params[3];

	request->Perform("GET", nullptr, callback, value);

	handlesys->FreeHandle(params[1], &sec);

	return 1;
}

static cell_t PerformPostRequest(IPluginContext *pContext, const cell_t *params)
{
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	json_t *data = GetJSONFromHandle(pContext, params[2]);
	if (data == nullptr)
	{
		return 0;
	}

	IPluginFunction *callback = pContext->GetFunctionById(params[3]);
	cell_t value = params[4];

	request->Perform("POST", data, callback, value);

	handlesys->FreeHandle(params[1], &sec);

	return 1;
}

static cell_t PerformPutRequest(IPluginContext *pContext, const cell_t *params)
{
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	json_t *data = GetJSONFromHandle(pContext, params[2]);
	if (data == nullptr)
	{
		return 0;
	}

	IPluginFunction *callback = pContext->GetFunctionById(params[3]);
	cell_t value = params[4];

	request->Perform("PUT", data, callback, value);

	handlesys->FreeHandle(params[1], &sec);

	return 1;
}

static cell_t PerformPatchRequest(IPluginContext *pContext, const cell_t *params)
{
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	json_t *data = GetJSONFromHandle(pContext, params[2]);
	if (data == nullptr)
	{
		return 0;
	}

	IPluginFunction *callback = pContext->GetFunctionById(params[3]);
	cell_t value = params[4];

	request->Perform("PATCH", data, callback, value);

	handlesys->FreeHandle(params[1], &sec);

	return 1;
}

static cell_t PerformDeleteRequest(IPluginContext *pContext, const cell_t *params)
{
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	IPluginFunction *callback = pContext->GetFunctionById(params[2]);
	cell_t value = params[3];

	request->Perform("DELETE", nullptr, callback, value);

	handlesys->FreeHandle(params[1], &sec);

	return 1;
}

static cell_t PerformDownloadFile(IPluginContext *pContext, const cell_t *params)
{
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	char *path;
	pContext->LocalToString(params[2], &path);

	IPluginFunction *callback = pContext->GetFunctionById(params[3]);
	IPluginFunction *progresscallback = pContext->GetFunctionById(params[4]);
	cell_t value = params[5];

	request->DownloadFile(path, callback, progresscallback ,value);

	handlesys->FreeHandle(params[1], &sec);

	return 1;
}

static cell_t PerformUploadFile(IPluginContext *pContext, const cell_t *params)
{
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	char *path;
	pContext->LocalToString(params[2], &path);

	IPluginFunction *callback = pContext->GetFunctionById(params[3]);
	IPluginFunction *progresscallback = pContext->GetFunctionById(params[4]);
	cell_t value = params[5];

	request->UploadFile(path, callback, progresscallback ,value);
	
	handlesys->FreeHandle(params[1], &sec);

	return 1;
}

static cell_t PerformPostForm(IPluginContext *pContext, const cell_t *params)
{
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	IPluginFunction *callback = pContext->GetFunctionById(params[2]);
	cell_t value = params[3];

	request->PostForm(callback, value);

	handlesys->FreeHandle(params[1], &sec);

	return 1;
}

static cell_t GetRequestConnectTimeout(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	return request->GetConnectTimeout();
}

static cell_t SetRequestConnectTimeout(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	request->SetConnectTimeout(params[2]);

	return 1;
}

static cell_t GetRequestMaxRedirects(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	return request->GetMaxRedirects();
}

static cell_t SetRequestMaxRedirects(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	request->SetMaxRedirects(params[2]);

	return 1;
}

static cell_t GetRequestMaxRecvSpeed(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	return request->GetMaxRecvSpeed();
}

static cell_t SetRequestMaxRecvSpeed(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	request->SetMaxRecvSpeed(params[2]);

	return 1;
}

static cell_t GetRequestMaxSendSpeed(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	return request->GetMaxSendSpeed();
}

static cell_t SetRequestMaxSendSpeed(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	request->SetMaxSendSpeed(params[2]);

	return 1;
}

static cell_t GetRequestTimeout(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	return request->GetTimeout();
}

static cell_t SetRequestTimeout(IPluginContext *pContext, const cell_t *params)
{
	HTTPRequest *request = GetRequestFromHandle(pContext, params[1]);
	if (request == nullptr)
	{
		return 0;
	}

	request->SetTimeout(params[2]);

	return 1;
}

static cell_t GetResponseDataLength(IPluginContext *pContext, const cell_t *params)
{
	HandleError err;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	struct HTTPResponse *response;
	Handle_t hndlResponse = static_cast<Handle_t>(params[1]);
	if ((err = handlesys->ReadHandle(hndlResponse, htHTTPResponse, &sec, (void **)&response)) != HandleError_None)
	{
		pContext->ReportError("Invalid HTTP response handle %x (error %d)", hndlResponse, err);
		return 0;
	}

	return response->size;
}

static cell_t GetResponseData(IPluginContext *pContext, const cell_t *params)
{
	HandleError err;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	struct HTTPResponse *response;
	Handle_t hndlResponse = static_cast<Handle_t>(params[1]);
	if ((err = handlesys->ReadHandle(hndlResponse, htHTTPResponse, &sec, (void **)&response)) != HandleError_None)
	{
		pContext->ReportError("Invalid HTTP response handle %x (error %d)", hndlResponse, err);
		return BAD_HANDLE;
	}

	/* Return the same handle every time we get the HTTP response data */
	if (response->hndlData == BAD_HANDLE)
	{
		json_error_t error;
		response->data = json_loads(response->body, 0, &error);
		if (response->data == nullptr)
		{
			pContext->ReportError("Invalid JSON in line %d, column %d: %s", error.line, error.column, error.text);
			return BAD_HANDLE;
		}

		response->hndlData = handlesys->CreateHandleEx(htJSON, response->data, &sec, nullptr, &err);
		if (response->hndlData == BAD_HANDLE)
		{
			json_decref(response->data);

			pContext->ReportError("Could not create data handle (error %d)", err);
			return BAD_HANDLE;
		}
	}

	return response->hndlData;
}

static cell_t GetResponseStr(IPluginContext *pContext, const cell_t *params)
{
	HandleError err;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	struct HTTPResponse *response;
	Handle_t hndlResponse = static_cast<Handle_t>(params[1]);
	if ((err = handlesys->ReadHandle(hndlResponse, htHTTPResponse, &sec, (void **)&response)) != HandleError_None)
	{
		pContext->ReportError("Invalid HTTP response handle %x (error %d)", hndlResponse, err);
		return 0;
	}

	pContext->StringToLocalUTF8(params[2], params[3], response->body, nullptr);

	return 1;
}

static cell_t GetResponseStatus(IPluginContext *pContext, const cell_t *params)
{
	HandleError err;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	struct HTTPResponse *response;
	Handle_t hndlResponse = static_cast<Handle_t>(params[1]);
	if ((err = handlesys->ReadHandle(hndlResponse, htHTTPResponse, &sec, (void **)&response)) != HandleError_None)
	{
		pContext->ReportError("Invalid HTTP response handle %x (error %d)", hndlResponse, err);
		return 0;
	}

	return response->status;
}

static cell_t GetResponseHeader(IPluginContext *pContext, const cell_t *params)
{
	HandleError err;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());

	struct HTTPResponse *response;
	Handle_t hndlResponse = static_cast<Handle_t>(params[1]);
	if ((err = handlesys->ReadHandle(hndlResponse, htHTTPResponse, &sec, (void **)&response)) != HandleError_None)
	{
		pContext->ReportError("Invalid HTTP response handle %x (error %d)", hndlResponse, err);
		return 0;
	}

	char *name;
	pContext->LocalToString(params[2], &name);

	std::string lowercaseName(name);
	for (size_t i = 0; i < lowercaseName.size(); i++)
	{
		lowercaseName[i] = tolower(lowercaseName[i]);
	}

	HTTPHeaderMap::Result header = response->headers.find(lowercaseName.c_str());
	if (!header.found())
	{
		return 0;
	}

	pContext->StringToLocalUTF8(params[3], params[4], header->value.c_str(), nullptr);

	return 1;
}

const sp_nativeinfo_t http_natives[] =
	{
		{"HTTPRequest.HTTPRequest", 				CreateRequest},
		{"HTTPRequest.AppendFormParam", 			AppendRequestFormParam},
		{"HTTPRequest.AppendQueryParam", 			AppendRequestQueryParam},
		{"HTTPRequest.SetBasicAuth", 				SetRequestBasicAuth},
		{"HTTPRequest.SetHeader", 					SetRequestHeader},
		{"HTTPRequest.SetProxy", 					SetProxy},
		{"HTTPRequest.Get", 						PerformGetRequest},
		{"HTTPRequest.Post", 						PerformPostRequest},
		{"HTTPRequest.Put", 						PerformPutRequest},
		{"HTTPRequest.Patch", 						PerformPatchRequest},
		{"HTTPRequest.Delete", 						PerformDeleteRequest},
		{"HTTPRequest.DownloadFile", 				PerformDownloadFile},
		{"HTTPRequest.UploadFile", 					PerformUploadFile},
		{"HTTPRequest.PostForm", 					PerformPostForm},
		{"HTTPRequest.ConnectTimeout.get", 			GetRequestConnectTimeout},
		{"HTTPRequest.ConnectTimeout.set", 			SetRequestConnectTimeout},
		{"HTTPRequest.MaxRedirects.get", 			GetRequestMaxRedirects},
		{"HTTPRequest.MaxRedirects.set", 			SetRequestMaxRedirects},
		{"HTTPRequest.MaxRecvSpeed.get", 			GetRequestMaxRecvSpeed},
		{"HTTPRequest.MaxRecvSpeed.set", 			SetRequestMaxRecvSpeed},
		{"HTTPRequest.MaxSendSpeed.get", 			GetRequestMaxSendSpeed},
		{"HTTPRequest.MaxSendSpeed.set", 			SetRequestMaxSendSpeed},
		{"HTTPRequest.Timeout.get", 				GetRequestTimeout},
		{"HTTPRequest.Timeout.set", 				SetRequestTimeout},
		{"HTTPResponse.ResponseDataLength.get", 	GetResponseDataLength},
		{"HTTPResponse.Data.get", 					GetResponseData},
		{"HTTPResponse.GetResponseStr", 			GetResponseStr},
		{"HTTPResponse.Status.get", 				GetResponseStatus},
		{"HTTPResponse.GetHeader", 					GetResponseHeader},

		{nullptr, 									nullptr}
};
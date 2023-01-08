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

#ifndef SM_RIPEXT_HTTPFILECONTEXT_H_
#define SM_RIPEXT_HTTPFILECONTEXT_H_

#include <stdio.h>
#include "extension.h"

class HTTPFileContext : public IHTTPContext
{
public:
	HTTPFileContext(bool isUpload, const std::string &url, const std::string &path,
					struct curl_slist *headers, IPluginFunction *callback, IPluginFunction *progressCallback, cell_t value,
					long connectTimeout, long maxRedirects, long timeout, curl_off_t maxSendSpeed, curl_off_t maxRecvSpeed,
					bool useBasicAuth, const std::string &username, const std::string &password, const std::string &proxy);
	~HTTPFileContext();

public: // IHTTPContext
	bool InitCurl();
	void OnCompleted();
	void setProgressData(curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow);
	IPluginFunction *getProgressFunction() { return progressFunction; };
	bool getIsuplaod() { return isUpload; };
	curl_off_t getdltotal() { return dltotal; };
	curl_off_t getdlnow() { return dlnow; };
	curl_off_t getultotal() { return ultotal; };
	curl_off_t getulnow() { return ulnow; };

private:
	FILE *file = nullptr;
	curl_off_t dltotal;
	curl_off_t dlnow;
	curl_off_t ultotal;
	curl_off_t ulnow;

	bool isUpload;
	const std::string url;
	const std::string path;
	struct curl_slist *headers;
	IPluginFunction *callback;
	IPluginFunction *progressFunction;
	cell_t value;
	char error[CURL_ERROR_SIZE] = {'\0'};
	long connectTimeout;
	long maxRedirects;
	long timeout;
	curl_off_t maxSendSpeed;
	curl_off_t maxRecvSpeed;
	bool useBasicAuth;
	const std::string username;
	const std::string password;
	const std::string proxy;
};

off_t FileSize(FILE *fd);

#endif // SM_RIPEXT_HTTPFILECONTEXT_H_
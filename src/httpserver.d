module exent.httpserver;

import std.concurrency;
import std.conv;
import std.socket;
import std.stdio;
import std.string;

import core.thread; // TODO: remove this along with main()

public:
shared class HttpRequestHandler {
public:
	void setStaticResponse(string path, HttpMessage response) {
		staticResponses[path] = response;
	}

protected:
	HttpMessage handleDynamicRequest(HttpMessageRequest request) {
		HttpMessage response;
		response.startLine = "HTTP/1.1 200 OK";
		response.content = "It works!";
		response.header = "Content-Length: " ~ to!string(response.content.length);
		return response;
	}

	HttpMessage handleBadRequest() {
		HttpMessage response;
		response.startLine = "HTTP/1.1 400 Bad Request";
		response.content = "400 - Bad Request";
		response.header = "Content-Length: " ~ to!string(response.content.length);
		return response;
	}

	HttpMessage handleNotFound() {
		HttpMessage response;
		response.startLine = "HTTP/1.1 404 Not Found";
		response.content = "404 - Not Found";
		response.header = "Content-Length: " ~ to!string(response.content.length);
		return response;
	}

	HttpMessage handleNotImplemented() {
		HttpMessage response;
		response.startLine = "HTTP/1.1 501 Not Implemented";
		response.content = "501 - Not Implemented";
		response.header = "Content-Length: " ~ to!string(response.content.length);
		return response;
	}

private:
	HttpMessage[string] staticResponses;

	HttpMessage handle(HttpMessage httpMessage) {
		HttpMessageRequest request = parseRequest(httpMessage);
		if (request.method == "ERROR")
			return handleBadRequest();
		if (request.method != "GET")
			return handleNotImplemented();
		if (request.path in staticResponses)
			return staticResponses[request.path];
		return handleDynamicRequest(request);
	}

	HttpMessageRequest parseRequest(HttpMessage request) {
		string[] entries = split(request.startLine);
		long pos = indexOf(entries[1], '?');
		return HttpMessageRequest(entries[0], entries[1][0 .. pos], entries[1][pos + 1 .. $], entries[2], request);
	}
}

struct HttpMessage {
	string startLine;
	string header;
	string content;
}

struct HttpMessageRequest {
	string method;
	string path;
	string query;
	string protocol;
	HttpMessage httpMessage;
	alias httpMessage this;
}

struct ServerSettings {
	ushort port = 8080;
	int maxConnections = 100;
	int connectionQueueSize = 10;
	int connectionTimeoutMs = 60000;
}

bool startServer(shared HttpRequestHandler handler, ServerSettings settings) {
	if (settings.port in listeners) {
		/* already a listener for this port */
		return false;
	}
	listeners[settings.port] = spawn(&listen, handler, settings);
	return true;
}

/* TODO: temporary for testing, remove */
void main() {
	startServer(new HttpRequestHandler(), ServerSettings());
	Thread.sleep(dur!"seconds"(10));
}

private:
Tid[ushort] listeners;

void listen(shared HttpRequestHandler handler, ServerSettings settings) {
	Socket listener = new TcpSocket;
	scope (exit) {
		listener.shutdown(SocketShutdown.BOTH);
		listener.close();
	}
	listener.blocking = true;
	listener.bind(new InternetAddress(settings.port));
	listener.listen(settings.connectionQueueSize);
	int threads = 0;
	bool active = true;
	while (active) {
		if (threads >= settings.maxConnections) {
			// TODO: receive(... { --threads; })
		}
		spawn(&handle, handler, settings, cast(shared) listener.accept());
		++threads;
		// TODO: while (something) receiveTimeout(dur!"usecs"(1), ... { --threads; });
		writeln("listener.accept() stopped blocking");
		receiveTimeout(dur!"usecs"(1), (OwnerTerminated) { active = false; }); 
	}
}

void handle(shared HttpRequestHandler handler, ServerSettings settings, shared Socket ssocket) {
	Socket socket = cast(Socket) ssocket; // nice, eh?
	scope (exit) {
		// TODO: send()
		socket.shutdown(SocketShutdown.BOTH);
		socket.close();
	}
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"msecs"(settings.connectionTimeoutMs));
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"msecs"(settings.connectionTimeoutMs));
	HttpMessage request;
	int status = 0;
	while (status == 0) {
		char[4096] buffer;
		long result = socket.receive(buffer);
		switch (result) {
		case Socket.ERROR:
			writeln("Connection error");
			/* fallthrough */

		case 0:
			writeln("Connection closed");
			socket.close();
			return;

		default:
			writefln("Received %s bytes (blocking: %s) from %s: %s", result, socket.blocking, socket.remoteAddress(), buffer[0 .. result]);
			if (request.startLine.length == 0) {
				long pos = indexOf(buffer, cast(char[]) [13, 10]);
				if (pos == -1) {
					writeln("<CR><LF> not found in first packet, presumably broken HTTP request");
					status = 400;
					break;
				}
				request.startLine = cast(string) buffer[0 .. pos];
				long headerStart = pos + 2;
				pos = indexOf(buffer[headerStart .. $], cast(char[]) [13, 10, 13, 10]);
				if (pos == -1) {
					writeln("<CR><LF><CR><LF> not found in first packet, presumably broken HTTP request");
					status = 400;
					break;
				}
				pos += headerStart; // we only searched a slice of buffer, need to add what we skipped
				writefln("<CR><LF><CR><LF> position: %s", pos);
				request.header = cast(string) buffer[headerStart .. pos];
				writefln("Start line: %s", request.startLine);
				writefln("Header:\n%s", request.header);
				long contentStart = pos + 4;
				writefln("Content start: %s", contentStart);
				if (contentStart < result)
					request.content = cast(string) buffer[contentStart .. result];
				writefln("Content: %s", request.content);
				/* TODO: figure out if we got a body (i.e. "Content-Length" header, etc. see: http://tools.ietf.org/html/rfc2616#section-4.4) */
				status = 200;
			} else {
				request.content ~= buffer[0 .. result];
			}
			break;
		}
	}
	HttpMessage response;
	switch (status) {
	case 200:
		response = handler.handle(request);
		break;

	default:
		response = handler.handleBadRequest();
		break;
	}
	char[] buffer;
	buffer ~= response.startLine;
	buffer ~= [13, 10];
	buffer ~= response.header;
	buffer ~= [13, 10, 13, 10];
	buffer ~= response.content;
	writefln("Sending to client: %s", buffer);
	bool active = true;
	while (active) {
		long sent = socket.send(buffer);
		if (sent < buffer.length)
			buffer = buffer[sent .. $];
		else
			active = false;
	}
}

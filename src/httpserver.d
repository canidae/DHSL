module exent.httpserver;

import std.concurrency;
import std.conv;
import std.socket;
import std.stdio;
import std.string;

import core.thread; // TODO: remove this along with main()

public:
immutable int STATUS_OK = 200;
immutable int BAD_REQUEST = 400;
immutable int NOT_FOUND = 404;
immutable int NOT_IMPLEMENTED = 501;

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

shared interface HttpRequestHandler {
	HttpMessage handle(HttpMessageRequest request, Address local, Address remote);
}

shared class DefaultHttpRequestHandler : HttpRequestHandler {
protected:
	override HttpMessage handle(HttpMessageRequest request, Address local, Address remote) {
		HttpMessage response;
		response.startLine = "HTTP/1.1 200 OK";
		response.content = "This is the default handler for requests that were handled correctly. If you see this message it means no handler was defined to handle the requested path.\n\n";
		response.content ~= "Request details:\n";
		response.content ~= "Method: " ~ request.method ~ "\n";
		response.content ~= "Path: " ~ request.path ~ "\n";
		response.content ~= "Query: " ~ request.query ~ "\n";
		response.content ~= "Protocol: " ~ request.protocol ~ "\n";
		response.content ~= "Header: " ~ request.header ~ "\n";
		response.content ~= "Content: " ~ request.content ~ "\n\n";
		response.content ~= "Local address: " ~ local.toString() ~ "\n";
		response.content ~= "Remote address: " ~ remote.toString();
		response.header = "Content-Length: " ~ to!string(response.content.length);
		return response;
	}

	HttpMessage handleError(int errorCode, HttpMessage request, Address local, Address remote) {
		HttpMessage response;
		switch (errorCode) {
		case BAD_REQUEST:
			response.startLine = "HTTP/1.1 400 Bad Request";
			response.content = "400 - Bad Request";
			break;

		case NOT_FOUND:
			response.startLine = "HTTP/1.1 404 Not Found";
			response.content = "404 - Not Found";
			break;

		case NOT_IMPLEMENTED:
			response.startLine = "HTTP/1.1 501 Not Implemented";
			response.content = "501 - Not Implemented";
			break;

		default:
			response.startLine = "HTTP/1.1 500 Internal Server Error";
			response.content = "500 - Internal Server Error";
			break;
		}
		response.header = "Content-Length: " ~ to!string(response.content.length);
		return response;
	}
}

shared class HttpServer {
public:
	this(ServerSettings settings, shared DefaultHttpRequestHandler defaultHandler = new DefaultHttpRequestHandler()) {
		this.settings = cast(shared) settings; // XXX: does shared struct even make any sense?
		this.defaultHandler = defaultHandler;
		listenerThread = cast(shared) spawn(&listen, this);
	}

	void addHandler(string path, shared HttpRequestHandler handler) {
		handlers[path] = handler;
	}

private:
	Tid listenerThread;
	ServerSettings settings;
	HttpRequestHandler[string] handlers;
	DefaultHttpRequestHandler defaultHandler;
}

/* TODO: temporary for testing, remove */
void main() {
	HttpServer httpServer = new HttpServer(ServerSettings());
	Thread.sleep(dur!"seconds"(10));
}

/* stuff below this line is not that interesting for users */
private:
void listen(shared HttpServer server) {
	Socket listener = new TcpSocket;
	scope (exit) {
		listener.shutdown(SocketShutdown.BOTH);
		listener.close();
	}
	listener.blocking = true;
	listener.bind(new InternetAddress(server.settings.port));
	listener.listen(server.settings.connectionQueueSize);
	int threads = 0;
	bool active = true;
	while (active) {
		if (threads >= server.settings.maxConnections) {
			// TODO: receive(... { --threads; })
		}
		spawn(&handle, server, cast(shared) listener.accept());
		++threads;
		// TODO: while (something) receiveTimeout(dur!"usecs"(1), ... { --threads; });
		writeln("listener.accept() stopped blocking");
		receiveTimeout(dur!"usecs"(1), (OwnerTerminated) { active = false; }); 
	}
}

void handle(shared HttpServer server, shared Socket ssocket) {
	Socket socket = cast(Socket) ssocket; // nice, eh?
	scope (exit) {
		// TODO: send()
		socket.shutdown(SocketShutdown.BOTH);
		socket.close();
	}
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"msecs"(server.settings.connectionTimeoutMs));
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"msecs"(server.settings.connectionTimeoutMs));
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
					status = BAD_REQUEST;
					break;
				}
				request.startLine = cast(string) buffer[0 .. pos];
				long headerStart = pos + 2;
				pos = indexOf(buffer[headerStart .. $], cast(char[]) [13, 10, 13, 10]);
				if (pos == -1) {
					writeln("<CR><LF><CR><LF> not found in first packet, presumably broken HTTP request");
					status = BAD_REQUEST;
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
				status = STATUS_OK;
			} else {
				request.content ~= buffer[0 .. result];
			}
			break;
		}
	}
	HttpMessage response;
	HttpMessageRequest parsedRequest;
	if (status == STATUS_OK) {
		parsedRequest = parseRequest(request);
		if (parsedRequest.method == "ERROR")
			status = BAD_REQUEST;
		else if (parsedRequest.method != "GET")
			status = NOT_IMPLEMENTED;
	}
	if (status == STATUS_OK) {
		shared HttpRequestHandler handler;
		if (parsedRequest.path in server.handlers)
			handler = server.handlers[parsedRequest.path];
		else
			handler = server.defaultHandler;
		response = handler.handle(parsedRequest, socket.localAddress(), socket.remoteAddress());
	} else {
		server.defaultHandler.handleError(status, request, socket.localAddress(), socket.remoteAddress());
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

HttpMessageRequest parseRequest(HttpMessage request) {
	string[] entries = split(request.startLine);
	long pos = indexOf(entries[1], '?');
	return HttpMessageRequest(entries[0], entries[1][0 .. pos], entries[1][pos + 1 .. $], entries[2], request);
}

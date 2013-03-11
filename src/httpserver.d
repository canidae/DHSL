module exent.httpserver;

import std.concurrency;
import std.conv;
import std.datetime;
import std.file;
import std.socket;
import std.stdio;
import std.string;

import core.thread; // TODO: remove this along with main()

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
	int maxConnections = 2;
	int connectionQueueSize = 10;
	int connectionTimeoutMs = 60000;
}

shared interface HttpRequestHandler {
	HttpMessage handle(HttpMessageRequest request, Address local, Address remote);
}

shared class StaticHttpRequestHandler : HttpRequestHandler {
	this(HttpMessage response) {
		this.response = response;
	}

	this(string content) {
		string header = "Content-Length: " ~ to!string(content.length);
		this(header, content);
	}

	this(string header, string content) {
		response.startLine = "HTTP/1.1 200 OK";
		response.header = header;
		response.content = content;
	}

protected:
	HttpMessage response;

	override HttpMessage handle(HttpMessageRequest, Address local, Address remote) {
		writeln("Static handler");
		return response;
	}
}

shared class HttpRequestErrorHandler {
protected:
	HttpMessage handleError(int errorCode, HttpMessage request, Address local, Address remote) {
		HttpMessage response;
		switch (errorCode) {
		case BAD_REQUEST:
			response.startLine = "HTTP/1.1 400 Bad Request";
			response.content = "400 - Bad Request";
			break;

		case NOT_FOUND:
			response.startLine = "HTTP/1.1 404 Not Found";
			response.content = "The requested resource was not found.\n\n";
			response.content ~= "Request details:\n";
			response.content ~= "Start line: " ~ request.startLine ~ "\n";
			response.content ~= "Header: " ~ request.header ~ "\n";
			response.content ~= "Content: " ~ request.content ~ "\n\n";
			response.content ~= "Local address: " ~ local.toString() ~ "\n";
			response.content ~= "Remote address: " ~ remote.toString();
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
	this(ServerSettings settings, shared HttpRequestErrorHandler errorHandler = new HttpRequestErrorHandler()) {
		this.settings = cast(shared) settings; // XXX: does shared struct even make any sense?
		this.errorHandler = errorHandler;
		//listenerThread = cast(shared) spawn(&listenOld, this);
	}

	void addHandler(string path, shared HttpRequestHandler handler) {
		handlers[path] = handler;
	}

private:
	Tid listenerThread;
	ServerSettings settings;
	HttpRequestHandler[string] handlers;
	HttpRequestErrorHandler errorHandler;
}

void addStaticResponses(HttpServer server, string path) {
	if (server is null || path is null)
		return;
	writeln("Reading files from: " ~ path);
	foreach (DirEntry f; dirEntries(path, SpanMode.depth)) {
		if (f.name[$ - 4 .. $] == ".swp")
			continue;
		string serverPath = f.name[path.length .. $];
		writeln("Adding static response to path: " ~ serverPath);
		//server.addHandler(serverPath, new StaticHttpRequestHandler(readText(f.name)));
	}
}

/* TODO: temporary for testing, remove */
void main() {
	HttpServer server = new HttpServer(ServerSettings());
	addStaticResponses(server, "/home/canidae/projects/dhsl/src");
	listen(ServerSettings());
}

/* stuff below this line is not that interesting for users */
private:
struct Connection {
	Socket socket;
	char[] data;
	SysTime lastAction;
}

void listen(ServerSettings settings) {
	Socket listener = new TcpSocket;
	scope (exit) {
		listener.shutdown(SocketShutdown.BOTH);
		listener.close();
	}
	listener.blocking = false;
	listener.bind(new InternetAddress(settings.port));
	listener.listen(settings.connectionQueueSize);
	writeln("Listening on port ", settings.port);

	SocketSet socketSet = new SocketSet(settings.maxConnections + 5); // TODO: not sure why it has to be +5, would expect +1 (for the listener) should be enough
	Connection[] connections;

	bool active = true;
	while (active) {
		socketSet.reset();
		socketSet.add(listener);
		foreach (Connection connection; connections)
			socketSet.add(connection.socket);

		Socket.select(socketSet, null, null);
		int connectionIndex = 0;
		SysTime minTime = Clock.currTime() - dur!("msecs")(settings.connectionTimeoutMs);
		while (connectionIndex < connections.length) {
			if (socketSet.isSet(connections[connectionIndex].socket)) {
				// more data available for socket, read it
				char[64] buffer; // TODO: larger buffer, small for testing
				auto read = connections[connectionIndex].socket.receive(buffer);
				if (read > 0) {
					connections[connectionIndex].data ~= buffer[0 .. read];
					connections[connectionIndex].lastAction = Clock.currTime();
					++connectionIndex;
					continue; // we're not done, expect more data later, continue to next socket
				} else if (read == Socket.ERROR) {
					writeln("Connection error");
				} else {
					writeln("Connection closed");
				}
				writefln("Received %s bytes from %s", connections[connectionIndex].data.length, connections[connectionIndex].socket.remoteAddress().toString());
			} else if (connections[connectionIndex].lastAction < minTime) {
				// this socket has timed out, remove it
				writefln("Closing timed-out connection from %s after receiving %s bytes", connections[connectionIndex].socket.remoteAddress().toString(), connections[connectionIndex].data.length);
			} else {
				// no updates for this socket, continue to next
				++connectionIndex;
				continue;
			}
			connections[connectionIndex].socket.close();
			if (connectionIndex != connections.length - 1)
				connections[connectionIndex] = connections[$ - 1];
			connections = connections[0 .. $ - 1];
			writeln("Open connections: ", connections.length);
		}

		if (socketSet.isSet(listener)) {
			// new connection
			Socket socket = listener.accept();
			if (connections.length >= settings.maxConnections) {
				int oldestIndex = 0;
				for (int index = 1; index < connections.length; ++index) {
					if (connections[index].lastAction < connections[oldestIndex].lastAction)
						oldestIndex = index;
				}
				writefln("Too many connections, forcing close of oldest connection, from %s after receiving %s bytes", connections[oldestIndex].socket.remoteAddress().toString(), connections[oldestIndex].data.length);
				connections[oldestIndex].socket.close();
				if (oldestIndex != connections.length - 1)
					connections[oldestIndex] = connections[$ - 1];
				connections = connections[0 .. $ - 1];
			}
			writefln("Socket from %s established", socket.remoteAddress().toString());
			connections ~= Connection(socket, [], Clock.currTime());
			writeln("Open connections: ", connections.length);
		}
	}
}

void listenOld(shared HttpServer server) {
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
		//receiveTimeout(dur!"usecs"(1), (OwnerTerminated) { active = false; }); 
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
	if (status == STATUS_OK && parsedRequest.path in server.handlers) {
		shared HttpRequestHandler handler = server.handlers[parsedRequest.path];
		response = handler.handle(parsedRequest, socket.localAddress(), socket.remoteAddress());
	} else {
		if (status == STATUS_OK)
			status = NOT_FOUND;
		response = server.errorHandler.handleError(status, request, socket.localAddress(), socket.remoteAddress());
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
	if (pos >= 0)
		return HttpMessageRequest(entries[0], entries[1][0 .. pos], entries[1][pos .. $], entries[2], request);
	return HttpMessageRequest(entries[0], entries[1], "", entries[2], request);
}

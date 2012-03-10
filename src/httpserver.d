module exent.httpserver;

import std.concurrency;
import std.socket;
import std.stdio;
import std.string;

import core.thread; // TODO: remove this along with main()

shared class HttpRequestHandler {
	HttpMessage handle(HttpMessage request) {
		HttpMessage response;
		response.startLine = "HTTP/1.1 200 OK";
		response.content = "It works!";
		return response;
	}

	HttpMessage handleBadRequest() {
		HttpMessage response;
		response.content = "400 - Bad Request";
		return response;
	}
}

struct HttpMessage {
	string startLine;
	string header;
	string content;
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
	listeners[settings.port] = spawn(&listen2, handler, settings);
	return true;
}

/* TODO: temporary for testing, remove */
void main() {
	startServer(new HttpRequestHandler(), ServerSettings());
	Thread.sleep(dur!"seconds"(10));
}

private:
struct Connection {
	int id;
	Socket socket;
	char[] readBuffer;
	char[] writeBuffer;
}

Tid[ushort] listeners;

void listen(HttpRequestHandler handler, ServerSettings settings) {
	Socket listener = new TcpSocket;
	scope (exit) {
		listener.shutdown(SocketShutdown.BOTH);
		listener.close();
	}
	listener.blocking = false;
	listener.bind(new InternetAddress(settings.port));
	listener.listen(settings.connectionQueueSize);
	SocketSet readSet = new SocketSet(settings.maxConnections + 1);
	Connection[] connections;
	int connectionId = 0;
	bool active = true;
	while (active) {
		readSet.reset();
		readSet.add(listener);
		int tempConnectionId;
		char[] tempWriteBuffer;
		receiveTimeout(dur!"usecs"(1), (int connectionId, char[] writeBuffer) { tempConnectionId = connectionId; tempWriteBuffer = writeBuffer; });
		foreach (connection; connections) {
			if (connection.id == tempConnectionId)
				connection.writeBuffer = tempWriteBuffer;
			readSet.add(connection.socket);
		}
		if (Socket.select(readSet, null, null, 10000) > 0) {
			/* Socket.select() will remove all sockets from the set except the changed ones */
			if (readSet.isSet(listener)) {
				/* listener is in set, this means someone is contacting us */
				Socket socket = listener.accept();
				if (connections.length < settings.maxConnections) {
					/* we got room for another connection */
					writefln("Connection from %s established", socket.remoteAddress());
					connections ~= Connection(++connectionId, socket, [], []);
				} else {
					/* too many connections, refuse a new connection */
					writefln("Connection from %s dropped, too many connections", socket.remoteAddress());
					socket.close();
				}
			}
			int index = 0;
			while (index < connections.length) {
				/* any news from the established connections? */
				if (readSet.isSet(connections[index].socket)) {
					/* someone sent us a letter, let's read it */
					writefln("Socket is ready for reading: %s", connections[index].socket);
					char[4096] buffer;
					long result = connections[index].socket.receive(buffer);
					switch (result) {
					case Socket.ERROR:
						writeln("Connection error");
						/* fallthrough */

					case 0:
						writeln("Connection closed");
						connections[index].socket.close();
						if (index < connections.length)
							connections[index] = connections[$ - 1];
						connections = connections[0 .. $ - 1];
						continue; // skip incrementing index

					default:
						writefln("Received %s bytes from %s: %s", result, connections[index].socket.remoteAddress(), buffer[0 .. result]);
						connections[index].readBuffer ~= buffer[0 .. result];
						break;
					}
				}
				++index;
			}
		}
		receiveTimeout(dur!"usecs"(1), (OwnerTerminated) { active = false; }); 
	}
}

/* sigh */
void listen2(shared HttpRequestHandler handler, ServerSettings settings) {
	Socket listener = new TcpSocket;
	scope (exit) {
		listener.shutdown(SocketShutdown.BOTH);
		listener.close();
	}
	listener.blocking = true;
	listener.bind(new InternetAddress(settings.port));
	listener.listen(settings.connectionQueueSize);
	bool active = true;
	while (active) {
		spawn(&handle, handler, cast(shared) listener.accept());
		writeln("listener.accept() stopped blocking");
		receiveTimeout(dur!"usecs"(1), (OwnerTerminated) { active = false; }); 
	}
}

void handle(shared HttpRequestHandler handler, shared Socket ssocket) {
	Socket socket = cast(Socket) ssocket; // nice, eh?
	scope (exit) {
		socket.shutdown(SocketShutdown.BOTH);
		socket.close();
	}
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(5));
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(5));
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
	bool active = true;
	while (active) {
		long sent = socket.send(buffer);
		if (sent < buffer.length)
			buffer = buffer[sent .. $];
		else
			active = false;
	}
}

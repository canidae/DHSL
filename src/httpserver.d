module exent.httpserver;

import std.concurrency;
import std.socket;
import std.stdio;

import core.thread; // TODO: remove this along with main()

shared class HttpRequestHandler {
	Response handle(Request request) {
		Response response;
		response.content = "It works!";
		return response;
	}

	Response handleBadRequest() {
		Response response;
		response.content = "400 - Bad Request";
		return response;
	}
}

struct Request {
	string protocol;
	string host;
	int port;
	string path;
	string query;
	string method;
	string header;
	string content;
}

struct Response {
	int code;
	string headers;
	string content;
}

bool startServer(HttpRequestHandler handler, ushort port = 8080, int maxConnections = 100, int threads = 10, int connectionQueueSize = 10) {
	if (port in listeners) {
		/* already a listener for this port */
		return false;
	}
	listeners[port] = spawn(&listen, handler, port, maxConnections, connectionQueueSize);
	return true;
}

/* TODO: temporary for testing, remove */
void main() {
	startServer(new HttpRequestHandler());
	Thread.sleep(dur!"seconds"(3600));
}

private:
struct Connection {
	Socket socket;
	char[] readBuffer;
}

Tid[ushort] listeners;

void listen(HttpRequestHandler handler, ushort port, int maxConnections, int connectionQueueSize) {
	Socket listener = new TcpSocket;
	scope(exit) {
		listener.shutdown(SocketShutdown.BOTH);
		listener.close();
	}
	listener.blocking = false;
	listener.bind(new InternetAddress(port));
	listener.listen(connectionQueueSize);
	SocketSet set = new SocketSet(maxConnections + 1);
	Connection[] connections;
	bool active = true;
	while (active) {
		set.reset();
		set.add(listener);
		foreach (connection; connections)
			set.add(connection.socket);
		if (Socket.select(set, null, null, 1000000) > 0) {
			/* Socket.select() will remove all sockets from the set except the changed ones */
			if (set.isSet(listener)) {
				/* listener is in set, this means someone is contacting us */
				Socket socket = listener.accept();
				if (connections.length < maxConnections) {
					/* we got room for another connection */
					writefln("Connection from %s established", socket.remoteAddress());
					connections ~= Connection(socket, []);
				} else {
					/* too many connections, refuse a new connection */
					writefln("Connection from %s dropped, too many connections", socket.remoteAddress());
					socket.close();
				}
			}
			int index = 0;
			while (index < connections.length) {
				/* any news from the established connections? */
				if (set.isSet(connections[index].socket)) {
					/* someone sent us a letter, let's read it */
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
						break;

					default:
						writefln("Received %s bytes from %s: %s", result, connections[index].socket.remoteAddress(), buffer[0 .. result]);
						connections[index].readBuffer ~= buffer[0 .. result];
						++index;
						break;
					}
				} else {
					/* no action on this socket, go to next */
					++index;
				}
			}
		}
		receiveTimeout(dur!"usecs"(1), (OwnerTerminated) { active = false; }); 
	}
}

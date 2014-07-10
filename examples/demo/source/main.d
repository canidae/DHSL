import dhsl;
import std.stdio;

void main() {
	addDynamicHandler(new DynamicFileHttpHandler("source/dhsl/httpserver.d"));
	writeln("spawning listener thread");
	startServer(ServerSettings());
	writeln("sleeping 10 seconds");
	core.thread.Thread.sleep(dur!"seconds"(10));
	writeln("telling listener thread to shut down");
	stopServer();
	writeln("exiting");
}

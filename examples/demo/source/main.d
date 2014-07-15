import dhsl;

import std.stdio;

void main() {
    addHttpHandler(new DynamicFileHttpHandler("source/main.d"));
    writeln("spawning listener thread");
    startServer(ServerSettings());
    writeln("sleeping 1000 seconds");
    core.thread.Thread.sleep(dur!"seconds"(1000));
    writeln("telling listener thread to shut down");
    stopServer();
    writeln("exiting");
}

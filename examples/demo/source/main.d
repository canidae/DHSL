import dhsl;

import std.file;
import std.stdio;

class DynamicFileHttpHandler : HttpHandler {
    this(string path) {
        super(regex(path));
        _path = path;
    }

    override HttpResponse handle(HttpRequest request, Address remote) {
        HttpResponse response;
        try {
            response.content = cast(ubyte[]) readText(_path);
        } catch (Throwable t) {
            writeln(t);
        }
        return response;
    }

private:
    string _path;
}

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

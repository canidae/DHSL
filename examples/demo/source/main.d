import dhsl;

import std.file;
import std.stdio;
import std.regex;

class DynamicFileHttpHandler : HttpHandler {
    this(string path) {
        _path = path;
    }

    string httpPath() {
        return "/" ~ _path;
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

class StaticHttpHandler : HttpHandler {
    this(HttpResponse response) {
        _response = response;
    }
    
    HttpResponse handle(HttpRequest request, Address remote) {
        return _response;
    }

private:
    HttpResponse _response;
}

void main() {
    DynamicFileHttpHandler fileHandler = new DynamicFileHttpHandler("source/main.d");
    addHttpHandler(fileHandler.httpPath(), fileHandler);
    addHttpHandler("/", new StaticHttpHandler(HttpResponse(cast(ubyte[]) "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Hello World!</title></head><body><a href=\"source/main.d\">Source of demo app</a></body></html>")));
    writeln("spawning listener thread");
    startServer(ServerSettings());
    writeln("sleeping 1000 seconds");
    core.thread.Thread.sleep(dur!"seconds"(1000));
    writeln("telling listener thread to shut down");
    stopServer();
    writeln("exiting");
}

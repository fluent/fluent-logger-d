import core.thread;
import std.stdio;

import fluent.logger;

struct S
{
    string text = "D";
    ulong count = 0;
}

void main()
{
    Logger logger = new FluentLogger("debug", FluentLogger.Configuration());

    for (size_t i; i < 100; i++) {
        if (logger.post("test", S("Testing...", i)))
            writeln("Pong!");
        else
            writeln("Failed");

        Thread.sleep(dur!("msecs")(10));
    }

    destroy(logger);
    writeln("End");
}

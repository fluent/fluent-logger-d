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

    void worker()
    {
        for (size_t i; i < 100; i++) {
            if (logger.post("test", S("Testing...", i))) {
                if (i % 10 == 0)
                    writeln("Pong!");
            } else {
                writeln("Failed");
            }

            Thread.sleep(dur!("msecs")(10));
        }
    }

    auto group = new ThreadGroup();
    foreach (_; 0..5)
        group.create(&worker);
    group.joinAll();

    destroy(logger);
    writeln("End");
}

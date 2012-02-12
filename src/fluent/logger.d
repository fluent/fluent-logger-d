// Written in the D programming language.

/**
 * Fluent logger implementation.
 *
 * Fluentd is a missing event collector.
 *
 * Example:
 * -----
 * struct Event
 * {
 *     string text = "This is D";
 *     long   id   = 0;
 * }
 *
 * // Create a configuration
 * Configuration conf;
 * conf.host = "backend1";
 *
 * // Create a logger with tag prefix and configuration
 * auto logger = new FluentLogger("app", conf);
 *
 * // Write Event object with "test" tag to Fluentd 
 * logger.write("test", Event());
 * // Fluentd accepts {"text":"This is D","id":0} at "app.test" input
 * -----
 *
 * See_Also:
 *  $(LINK2 http://fluentd.org/, Welcome to Fluentd’s documentation!)
 *
 * Copyright: Copyright Masahiro Nakagawa 2012-.
 * License:   <a href="http://www.boost.org/LICENSE_1_0.txt">Boost License 1.0</a>.
 * Authors:   Masahiro Nakagawa
 */

module fluent.logger;

import std.array;
import std.datetime : Clock, SysTime;

import msgpack;
import socket;


/**
 * FluentLogger configuration
 *
 * TODO: Resolve host
 */
struct Configuration
{
    string host = "127.0.0.1";
    ushort port = 24224;
}


/**
 * $(D FluentLogger) is a $(D Fluentd) client
 */
class FluentLogger
{
  private:
    immutable string        prefix_;
    immutable Configuration config_;

    //Appender!(ubyte[]) buffer_;
    Socket!IPEndpoint socket_;

  public:
    this(in string prefix, in Configuration config)
    {
        prefix_ = prefix;
        config_ = config;

        connect();
    }

    ~this()
    {
        close();
    }

    void close()
    {
        if (socket_ !is null) {
            socket_.shutdown(SocketShutdown.BOTH);
            socket_.close();
            socket_ = null;
        }
    }

    void connect()
    {
        auto address = IPAddress(config_.host);
        auto family  = address.isIPv4 ? AddressFamily.INET : AddressFamily.INET6;
        socket_ = new Socket!IPEndpoint(family, SocketType.STREAM, ProtocolType.TCP);
        socket_.connect(IPEndpoint(address, config_.port));
    }

    void write(T)(in string tag, auto ref const T record)
    {
        write(tag, Clock.currTime(), record);
    }

    void write(T)(in string tag, in SysTime time, auto ref const T record)
    {
        auto completeTag = prefix_.length ? prefix_ ~ "." ~ tag : tag;
        return send(pack!true(completeTag, time.toUnixTime(), record));
    }


  private:
    void send(in ubyte[] data)
    {
        // TODO: Add error handling and buffering
        socket_.send(data);
    }
}

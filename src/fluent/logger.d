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
 * FluentLogger.Configuration conf;
 * conf.host = "backend1";
 *
 * // Create a logger with tag prefix and configuration
 * auto logger = new FluentLogger("app", conf);
 *
 * // Write Event object with "test" tag to Fluentd 
 * logger.post("test", Event());
 * // Fluentd accepts {"text":"This is D","id":0} at "app.test" input
 * -----
 *
 * See_Also:
 *  $(LINK2 http://fluentd.org/, Welcome to Fluentd’s documentation!)
 *
 * Copyright: Copyright Masahiro Nakagawa 2012-.
 * License:   <a href="http://www.apache.org/licenses/LICENSE-2.0">Apache License, Version 2.0</a>.
 * Authors:   Masahiro Nakagawa
 */

module fluent.logger;

import core.sync.mutex;
import std.array;
import std.datetime : Clock, SysTime;

debug import std.stdio;  // TODO: replace with std.log

import msgpack;
import socket;  // I don't understand std.socket API ;-(


/**
 * Base class for Fluent loggers
 */
abstract class Logger
{
    // should be changed to interface?
  protected:
    immutable string prefix_;


  public:
    @safe
    this(in string prefix)
    {
        prefix_ = prefix;
    }

    @property
    const(ubyte[]) pendings() const;

    void close();

    bool post(T)(in string tag, auto ref const T record)
    {
        return post(tag, Clock.currTime(), record);
    }

    bool post(T)(in string tag, in SysTime time, auto ref const T record)
    {
        auto completeTag = prefix_.length ? prefix_ ~ "." ~ tag : tag;
        return write(pack!true(completeTag, time.toUnixTime(), record));
    }

    bool write(in ubyte[] data);
}


class Tester : Logger
{
  private:
    ubyte[] buffer_;  // should have limit?
    Mutex mutex_;


  public:
    @safe
    this(in string prefix)
    {
        super(prefix);

        mutex_ = new Mutex();
    }

    @property
    override const(ubyte[]) pendings() const
    {
        synchronized(mutex_) {
            return buffer_;
        }
    }

    override void close()
    {
        buffer_ = null;
    }

    override bool write(in ubyte[] data)
    {
        synchronized(mutex_) {
            buffer_ ~= data;
        }

        return true;
    }
}


/**
 * $(D FluentLogger) is a $(D Fluentd) client
 */
class FluentLogger : Logger
{
  public:
    /**
     * FluentLogger configuration
     */
    struct Configuration
    {
        string host = "localhost";
        ushort port = 24224;
        // size_t bufferLimit = 4 * 1024 * 1024;
    }


  private:
    immutable Configuration config_;

    //Appender!(ubyte[]) buffer_;  // Appender's qualifiers are broken...
    ubyte[]            buffer_;  // should have limit?
    Socket!IPEndpoint  socket_;

    // for reconnection
    uint    errorNum_;
    SysTime errorTime_;

    // for multi-threading
    Mutex mutex_;


  public:
    @safe
    this(in string prefix, in Configuration config)
    {
        super(prefix);

        config_ = config;
        mutex_ = new Mutex();
    }

    ~this()
    {
        close();
    }

    @property
    override const(ubyte[]) pendings() const
    {
        synchronized(mutex_) {
            return buffer_;
        }
    }

    override void close()
    {
        synchronized(mutex_) {
            if (socket_ !is null) {
                if (buffer_.length > 0) {
                    try {
                        send(buffer_);
                        buffer_ = null;
                    } catch (const SocketException e) {
                        debug { writeln("Failed to flush logs"); }
                    }
                }

                socket_.shutdown(SocketShutdown.both);
                clear(socket_);
                socket_ = null;
            }
        }
    }

    override bool write(in ubyte[] data)
    {
        synchronized(mutex_) {
            buffer_ ~= data;
            if (!canWrite())
                return false;

            try {
                send(buffer_);
                buffer_ = buffer_.ptr[0..0];
            } catch (SocketException e) {
                clearSocket();
                throw e;
            }
        }

        return true;
    }


  private:
    @trusted
    void connect()
    {
        auto addrInfos = getAddressInfo(config_.host, SocketType.stream, ProtocolType.tcp);
        if (addrInfos is null)
            throw new Exception("Failed to resolve host: hsot = " ~ config_.host);

        // hostname sometimes provides many address informations
        foreach (i, ref addrInfo; addrInfos) {
            try {
                auto socket = new Socket!IPEndpoint(addrInfo);
                auto endpoint = IPEndpoint(addrInfo.ipAddress, config_.port);

                socket.connect(endpoint);
                socket_    = socket;
                errorNum_  = 0;
                errorTime_ = SysTime.init;

                debug { writeln("Connect to: host = ", config_.host, ", port = ", config_.port); }

                return;
            } catch (SocketException e) {
                clearSocket();

                // If all hosts can't be connected, raises an exeception
                if (i == addrInfos.length - 1) {
                    errorNum_++;
                    errorTime_ = Clock.currTime();

                    throw e;
                }
            }
        }
    }

    @trusted
    void send(in ubyte[] data)
    {
        if (socket_ is null)
            connect();

        socket_.send(data);

        debug { writeln("Sent: ", data.length, " bytes"); }
    }
    
    void clearSocket()
    {
        // reconnection at send method.
        if (socket_ !is null) {
            try {
                socket_.close();
            } catch (SocketException e) {
                // ignore close exception.
            }
        }
        socket_ = null;
    }

    enum ReconnectionWaitingMax = 60u;

    /* @safe */ @trusted
    bool canWrite()
    {
        // prevent useless reconnection
        if (errorTime_ != SysTime.init) {
            // TODO: more complex?
            uint secs = 2 ^^ errorNum_;
            if (secs > ReconnectionWaitingMax)
                secs = ReconnectionWaitingMax;

            if ((Clock.currTime() - errorTime_).get!"seconds"() < secs)
                return false;
        }

        return true;
    }
}

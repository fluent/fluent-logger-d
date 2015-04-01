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
 * 
 * // Disconnect and perform cleanup
 * logger.close(); // Or destroy(logger);
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

private import core.sync.mutex;
private import std.array;
private import std.datetime : Clock, SysTime;
private import std.socket : getAddress, lastSocketError, ProtocolType, Socket,
                            SocketException, SocketShutdown, SocketType, TcpSocket;

debug import std.stdio;  // TODO: replace with std.log

private import msgpack;

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

    /**
     * Pack the given $(D_PARAM record) using MessagePack and
     * write it with the current timestamp using $(D_PSYMBOL write).
     *
     * If a prefix was given when the logger was created the
     * tag is appended to the prefix when posting. This
     * allocation may be avoided by given a $(D_KEYWORD null)
     * prefix in the constructor and the full tag here.
     *
     * Params:
     *  tag = string used to tag the record
     *  record = data to be packed via msgpack and sent
     *
     * Returns: True if the data was successfully sent
     *          to the fluent server. False if the data
     *          was queued for sending later but no
     *          attempt was made to send to the remote
     *          host because of a previous error.
     * See_Also: write
     */
    bool post(T)(in string tag, auto ref const T record)
    {
        return post(tag, Clock.currTime(), record);
    }

    /**
     * Pack the given $(D_PARAM record) using MessagePack and
     * write it with the given timestamp using $(D_PSYMBOL write).
     *
     * If a prefix was given when the logger was created the
     * tag is appended to the prefix when posting. This
     * allocation may be avoided by giving a $(D_KEYWORD null)
     * prefix in the constructor and the full tag here.
     *
     * Params:
     *  tag = string used to tag the record
     *  time = timestamp of the event being logged
     *  record = data to be packed via msgpack and sent
     *
     * Returns: True if the data was successfully sent
     *          to the fluent server. False if the data
     *          was queued for sending later but no
     *          attempt was made to send to the remote
     *          host because of a previous error.
     * See_Also: write
     */
    bool post(T)(in string tag, in SysTime time, auto ref const T record)
    {
        auto completeTag = prefix_.length ? prefix_ ~ "." ~ tag : tag;
        return write(pack!true(completeTag, time.toUnixTime(), record));
    }

    /**
     * Write an array of ubyte to the logger.
     * Client code should generally use the post() functions
     * of $(D_PSYMBOL Logger) instead of calling write() directly.
     *
     * Params:
     *   data = The data to be written.
     * Returns: True if the data was successfully sent
     *          to the fluent host. False if the data
     *          was queued for sending later but no
     *          attempt was made to send to the remote
     *          host because of a previous error.
     * See_Also: post
     */
    bool write(in ubyte[] data);
}


class Tester : Logger
{
  private:
    ubyte[] buffer_;  // should have limit?
    Mutex mutex_;


  public:
    @trusted
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
 * $(D_PSYMBOL FluentLogger) is a $(D_PSYMBOL Fluentd) client
 */
class FluentLogger : Logger
{
  private import fluent.databuffer : dataBuffer, DataBuffer;
  public:
    /**
     * FluentLogger configuration
     */
    struct Configuration
    {
        string host = "localhost";
        ushort port = 24224;
        size_t initialBufferSize = 64;
    }


  private:
    immutable Configuration config_;

    DataBuffer!ubyte buffer_ = void;
    TcpSocket  socket_;

    // for reconnection
    uint    errorNum_;
    SysTime errorTime_;

    // for multi-threading
    Mutex mutex_;

  public:

    /**
     * Constructs a new $(D_PSYMBOL FluentLogger) instance using the given $(D_PSYMBOL Configuration).
     *
     * Params:
     *  prefix = Prefix to use before the tag for each post. May be null.
     *  config = Specifies the $(D_PSYMBOL Configuration) to use for this particular instance.
     */
    @trusted
    this(in string prefix, in Configuration config)
    {
        super(prefix);

        config_ = config;
        mutex_ = new Mutex();

        ubyte[] tmpBuf = new ubyte[config.initialBufferSize];
        buffer_ = dataBuffer(tmpBuf);
    }

    /**
     * Destructor.
     *
     * Closes the logger.
     */
    ~this()
    {
        close();
        buffer_.free();
    }

    /**
     * Returns:
     *  A slice into the buffer of data waiting to be sent that is only
     *  valid until the next post(), write(), or close().
     */
    @property
    override const(ubyte[]) pendings() const
    {
        synchronized(mutex_) {
            return buffer_[];
        }
    }

    /**
     * Flush the remaining data in the buffer and close the
     * connection to the remote fluent host.
     *
     * If the data in the buffer can't be sent it is discarded and
     * the buffer is cleared.
     *
     * It is possible to continue using the $(D_PSYMBOL FluentLogger) after close()
     * has been called. The next call to write (or post) will
     * open a new connection to the fluent host. But doing this is discouraged
     * because in general it is expected that no further operations
     * are performed after calling close() on implementations of $(D_PSYMBOL Logger).
     */
    override void close()
    {
        synchronized(mutex_) {
            if (socket_ !is null) {
                if (buffer_.length > 0) {
                    try {
                        send(buffer_[]);
                        buffer_.length = 0;
                    } catch (const SocketException e) {
                        debug { writeln("Failed to flush logs. ", buffer_.length, " bytes not sent."); }
                    }
                }

                clearSocket();
            }
        }
    }

    /**
     * Write an array of ubyte to the logger.
     * Client code should generally use the post() functions
     * of $(D_PSYMBOL Logger) instead of calling write() directly.
     *
     * Params:
     *   data = The data to be written.
     * Throws: $(D_PSYMBOL SocketException) if an error
     *          occurs sending data to the fluent host.
     * Returns: True if the data was successfully sent
     *          to the fluent host. False if the data
     *          was queued for sending later but no
     *          attempt was made to send to the remote
     *          host because of a previous error.
     * See_Also: post
     */
    override bool write(in ubyte[] data)
    {
        synchronized(mutex_) {
            buffer_.put(data);
            if (!canWrite())
                return false;

            try {
                send(buffer_[]);
                buffer_.length = 0;
            } catch (SocketException e) {
                errorNum_++;
                errorTime_ = Clock.currTime();
                clearSocket();
                throw e;
            }
        }

        return true;
    }


  private:
    /**
     * Connects to the remote host.
     *
     * Throws:
     *  $(D_PSYMBOL SocketException) if the connection fails.
     *  $(D_PSYMBOL Exception) if an address can't be found for the host.
     */
    @trusted
    void connect()
    {
        auto addresses = getAddress(config_.host, config_.port);
        if (addresses.length == 0)
            throw new Exception("Failed to resolve host: host = " ~ config_.host);

        // hostname sometimes provides many address informations
        foreach (i, ref address; addresses) {
            try {
                auto socket = new TcpSocket(address);
                socket_    = socket;
                errorNum_  = 0;
                errorTime_ = SysTime.init;

                debug { writeln("Connected to: host = ", config_.host, ", port = ", config_.port); }

                return;
            } catch (SocketException e) {
                clearSocket();

                // If all hosts can't be connected, raises an exeception
                if (i == addresses.length - 1) {
                    errorNum_++;
                    errorTime_ = Clock.currTime();

                    throw e;
                }
            }
        }
    }

    /**
     * Send the specified data to the fluent host.
     *
     * If not already connected to the fluent host
     * connect() is called. Therefore this function
     * throws the exceptions connect() throws in
     * addition to the exceptions listed here.
     *
     * See_Also: connect
     *
     * Params:
     *  data = The data to send.
     * Throws:
     *  $(D_PSYMBOL SocketException) if unable to send the data.
     */
    @trusted
    void send(in ubyte[] data)
    {
        if (socket_ is null)
            connect();

        auto bytesSent = socket_.send(data);
        if (bytesSent == Socket.ERROR) {
            throw new SocketException("Unable to send to socket. ", lastSocketError());
        }

        debug { writeln("Sent: ", data.length, " bytes"); }
    }
    
    /**
     * Close the existing socket connection to the fluent host, if any.
     */
    void clearSocket() nothrow
    {
        // reconnection at send method.
        if (socket_ !is null) {
            try {
                socket_.shutdown(SocketShutdown.BOTH);
                socket_.close();
            } catch (Exception e) {
                /* Ignore any exceptions. We're done with
                 * the socket anyway so they don't matter.
                 */
            }
        }
        socket_ = null;
    }

    /**
     * Specifies the maximum number of seconds to wait
     * to send data to the fluent host from the last
     * timestamp that an error was encountered.
     */
    enum ReconnectionWaitingMax = 60u;

    /**
     * Returns true if data should attempt to be
     * sent and false otherwise.
     *
     * If no errors have been encountered this function
     * will return true. As errors are encountered the
     * function will back off until at least $(D_PSYMBOL ReconnectionWaitingMax)
     * seconds have passed since the last error.
     */
    /* @safe */ @trusted
    bool canWrite()
    {
        // prevent useless reconnection
        if (errorTime_ != SysTime.init) {
            // TODO: more complex?
            uint secs = 2 ^^ errorNum_;
            if (secs > ReconnectionWaitingMax)
                secs = ReconnectionWaitingMax;

            if ((Clock.currTime() - errorTime_).total!"seconds"() < secs)
                return false;
        }

        return true;
    }
}

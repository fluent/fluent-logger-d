# Fluent logger

A structured event logger for Fluent

## Usage

```d
struct Event
{
    string text = "This is D";
    long   id   = 0;
}

// ...
import fluent.logger;

// Create a configuration
FluentLogger.Configuration conf;

// Create a logger with tag prefix and configuration
auto logger = new FluentLogger("app", conf);

// Write Event object with "test" tag to Fluentd 
logger.post("test", Event());

// Disconnect and perform cleanup
logger.close(); // Or destroy(logger);
```

In this result, Fluentd accepts ```{"text":"This is D","id":0}``` at "app.test" tag.

### Sharing logger

Currently, FluentLogger is not marked as ```shared```.
So, if you share a logger object accross threads, please use ```__gshared```.

## Build

    The library: dub build
    Documentation: dub build --build=docs
    Examples:
       Single-threaded: dub build --config=post-example
       Multi-threaded: dub build --config=post-mt-example

## TODO

* std.log support after Phobos accepts std.log
* Add some qualifiers (@safe, nothrow, shared, etc..)
* Windows support

## Link

* [Web site](http://fluentd.org/)

  Fluentd official site

* [Source repository](https://github.com/fluent/fluent-logger-d)

  Github repository

## Copyright

<table>
  <tr>
    <td>Author</td><td>Masahiro Nakagawa <repeatedly@gmail.com></td>
  </tr>
  <tr>
    <td>Copyright</td><td>Copyright (c) 2012- Masahiro Nakagawa</td>
  </tr>
  <tr>
    <td>License</td><td>Apache License, Version 2.0</td>
  </tr>
</table>

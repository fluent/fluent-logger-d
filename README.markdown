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
Configuration conf;

// Create a logger with tag prefix and configuration
auto logger = new FluentLogger("app", conf);

// Write Event object with "test" tag to Fluentd 
logger.write("test", Event());
```

In this result, Fluentd accepts ```{"text":"This is D","id":0}``` at "app.test" input source.

## TODO

* Add error handling
* Add buffering
* Make logger thread safety
* std.log support after Phobos accepts std.log
* Add other modules

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
    <td>License</td><td>Boost Software License, Version 1.0</td>
  </tr>
</table>

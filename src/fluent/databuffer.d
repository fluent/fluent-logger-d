/*
 * Copyright: 2014 by Digital Mars
 * License: $(LINK2 http://boost.org/LICENSE_1_0.txt, Boost License 1.0).
 * Authors: Walter Bright
 * Source: $(PHOBOSSRC std/internal/_scopebuffer.d)
 * 
 * This module is based on Walter Bright's ScopeBuffer with slight modification. 
 * https://raw.githubusercontent.com/WalterBright/phobos/master/std/internal/scopebuffer.d
 * http://forum.dlang.org/thread/ld2586$17f6$1@digitalmars.com
 * http://wiki.dlang.org/Std.buffer.scopebuffer
 * 
 * Modifications:
 * 
 * - Use size_t instead of uint. This makes it slower than Walter's original 
 * version but we don't have deal with hitting the 32-bit limit. 
 * 
 * - "T[] opSlice()" changed to "inout(T[]) opSlice() inout". 
 *
 */
 
module fluent.databuffer;


//debug=DataBuffer;

private import core.exception;
private import core.stdc.stdlib : realloc;
private import std.traits;

/**************************************
 *  encapsulates using a local array as a temporary buffer.
 * It is initialized with the local array that should be large enough for
 * most uses. If the need exceeds the size, DataBuffer will resize it
 * using malloc() and friends.
 *
 * DataBuffer is an OutputRange.
 *
 * Since DataBuffer potentially stores elements of type T in malloc'd memory,
 * those elements are not scanned when the GC collects. This can cause
 * memory corruption. Do not use DataBuffer when elements of type T point
 * to the GC heap.
 *
 * Example:
---
import core.stdc.stdio;
import DataBuffer.databuffer;
void main()
{
    char[2] buf = void;
    auto textbuf = DataBuffer!char(buf);
    scope(exit) textbuf.free(); // necessary for cleanup

    // Put characters and strings into textbuf, verify they got there
    textbuf.put('a');
    textbuf.put('x');
    textbuf.put("abc");
    assert(textbuf.length == 5);
    assert(textbuf[1..3] == "xa");
    assert(textbuf[3] == 'b');

    // Can shrink it
    textbuf.length = 3;
    assert(textbuf[0..textbuf.length] == "axa");
    assert(textbuf[textbuf.length - 1] == 'a');
    assert(textbuf[1..3] == "xa");

    textbuf.put('z');
    assert(textbuf[] == "axaz");

    // Can shrink it to 0 size, and reuse same memory
    textbuf.length = 0;
}
---
 * It is invalid to access DataBuffer's contents when DataBuffer goes out of scope.
 * Hence, copying the contents are necessary to keep them around:
---
import fluent.databuffer;
string cat(string s1, string s2)
{
    char[10] tmpbuf = void;
    auto textbuf = DataBuffer!char(tmpbuf);
    scope(exit) textbuf.free();
    textbuf.put(s1);
    textbuf.put(s2);
    textbuf.put("even more");
    return textbuf[].idup;
}
---
 * DataBuffer is intended for high performance usages in $(D @system) and $(D @trusted) code.
 * If used incorrectly, memory leaks and corruption can result. Be sure to use
 * $(D scope(exit) textbuf.free();) for proper cleanup, and do not refer to a DataBuffer
 * instance's contents after $(D DataBuffer.free()) has been called.
 *
 * The realloc parameter defaults to C's realloc(). Another can be supplied to override it.
 *
 * DataBuffer instances may be copied, as in:
---
textbuf = doSomething(textbuf, args);
---
 * which can be very efficent, but these must be regarded as a move rather than a copy.
 * Additionally, the code between passing and returning the instance must not throw
 * exceptions, otherwise when DataBuffer.free() is called, memory may get corrupted.
 */

@system
struct DataBuffer(T, alias realloc = core.stdc.stdlib.realloc)
	if (isAssignable!T &&
	    !hasElaborateDestructor!T &&
	    !hasElaborateCopyConstructor!T &&
	    !hasElaborateAssign!T)
{
	import core.stdc.string : memcpy;
	
	/**************************
     * Initialize with buf to use as scratch buffer space.
     * Params:
     *  buf = Scratch buffer space, must have length that is even
     * Example:
     * ---
     * ubyte[10] tmpbuf = void;
     * auto sbuf = DataBuffer!ubyte(tmpbuf);
     * ---
     * If buf was created by the same realloc passed as a parameter
     * to DataBuffer, then the contents of DataBuffer can be extracted without needing
     * to copy them, and DataBuffer.free() will not need to be called.
     */
	this(T[] buf)
		in
	{
		assert(!(buf.length & wasResized));    // assure even length of scratch buffer space
	}
	body
	{
		this.buf = buf.ptr;
		this.bufLen = buf.length;
	}
	
	unittest
	{
		ubyte[10] tmpbuf = void;
		auto sbuf = DataBuffer!ubyte(tmpbuf);
	}
	
	/**************************
     * Releases any memory used.
     * This will invalidate any references returned by the [] operator.
     * A destructor is not used, because that would make it not POD
     * (Plain Old Data) and it could not be placed in registers.
     */
	void free()
	{
		debug(DataBuffer) buf[0 .. bufLen] = 0;
		if (bufLen & wasResized)
			realloc(buf, 0);
		buf = null;
		bufLen = 0;
		used = 0;
	}
	
	/************************
     * Append element c to the buffer.
     * This member function makes DataBuffer an OutputRange.
     */
	void put(T c)
	{
		/* j will get enregistered, while used will not because resize() may change used
         */
		const j = used;
		if (j == bufLen)
		{
			resize(j * 2 + 16);
		}
		buf[j] = c;
		used = j + 1;
	}
	
	/************************
     * Append array s to the buffer.
     *
     * If $(D const(T)) can be converted to $(D T), then put will accept
     * $(D const(T)[] as input. It will accept a $(D T[]) otherwise.
     */
	private alias CT = Select!(is(const(T) : T), const(T), T);
	/// ditto
	void put(CT[] s)
	{
		const newlen = used + s.length;
		const len = bufLen;
		if (newlen > len)
		{
			resize(newlen <= len * 2 ? len * 2 : newlen);
		}
		buf[used .. newlen] = s[];
		used = newlen;
	}
	
	/******
     * Retrieve a slice into the result.
     * Returns:
     *  A slice into the temporary buffer that is only
     *  valid until the next put() or DataBuffer goes out of scope.
     */
	@system T[] opSlice(size_t lower, size_t upper)
	in
	{
		assert(lower <= bufLen);
		assert(upper <= bufLen);
		assert(lower <= upper);
	}
	body
	{
		return buf[lower .. upper];
	}
	
	/// ditto
	@system inout(T[]) opSlice() inout
	{
		assert(used <= bufLen);
		return buf[0 .. used];
	}
	
	/*******
     * Returns:
     *  the element at index i.
     */
	ref T opIndex(size_t i)
	{
		assert(i < bufLen);
		return buf[i];
	}
	
	/***
     * Returns:
     *  the number of elements in the DataBuffer
     */
	@property size_t length() const
	{
		return used;
	}
	
	/***
     * Used to shrink the length of the buffer,
     * typically to 0 so the buffer can be reused.
     * Cannot be used to extend the length of the buffer.
     */
	@property void length(size_t i)
	in
	{
		assert(i <= this.used);
	}
	body
	{
		this.used = i;
	}
	
	alias opDollar = length;
	
private:
	T* buf;
	size_t bufLen;
	enum wasResized = 1;         // this bit is set in bufLen if we control the memory
	size_t used;
	
	void resize(size_t newsize)
	{
		//writefln("%s: oldsize %s newsize %s", id, buf.length, newsize);
		newsize |= wasResized;
		void *newBuf = realloc((bufLen & wasResized) ? buf : null, newsize * T.sizeof);
		if (!newBuf)
			core.exception.onOutOfMemoryError();
		if (!(bufLen & wasResized))
		{
			memcpy(newBuf, buf, used * T.sizeof);
			debug(DataBuffer) buf[0 .. bufLen] = 0;
		}
		buf = cast(T*)newBuf;
		bufLen = newsize;
		
		/* This function is called only rarely,
         * inlining results in poorer register allocation.
         */
		version (DigitalMars)
			/* With dmd, a fake loop will prevent inlining.
             * Using a hack until a language enhancement is implemented.
             */
		while (1) { break; }
	}
}

unittest
{
	import core.stdc.stdio;
	import std.range;
	
	char[2] tmpbuf = void;
	{
		// Exercise all the lines of code except for assert(0)'s
		auto textbuf = DataBuffer!char(tmpbuf);
		scope(exit) textbuf.free();
		
		static assert(isOutputRange!(DataBuffer!char, char));
		
		textbuf.put('a');
		textbuf.put('x');
		textbuf.put("abc");         // tickle put([])'s resize
		assert(textbuf.length == 5);
		assert(textbuf[1..3] == "xa");
		assert(textbuf[3] == 'b');
		
		textbuf.length = textbuf.length - 1;
		assert(textbuf[0..textbuf.length] == "axab");
		
		textbuf.length = 3;
		assert(textbuf[0..textbuf.length] == "axa");
		assert(textbuf[textbuf.length - 1] == 'a');
		assert(textbuf[1..3] == "xa");
		
		textbuf.put(cast(dchar)'z');
		assert(textbuf[] == "axaz");
		
		textbuf.length = 0;                 // reset for reuse
		assert(textbuf.length == 0);
		
		foreach (char c; "asdf;lasdlfaklsdjfalksdjfa;lksdjflkajsfdasdfkja;sdlfj")
		{
			textbuf.put(c); // tickle put(c)'s resize
		}
		assert(textbuf[] == "asdf;lasdlfaklsdjfalksdjfa;lksdjflkajsfdasdfkja;sdlfj");
	} // run destructor on textbuf here
	
}

unittest
{
	string cat(string s1, string s2)
	{
		char[10] tmpbuf = void;
		auto textbuf = DataBuffer!char(tmpbuf);
		scope(exit) textbuf.free();
		textbuf.put(s1);
		textbuf.put(s2);
		textbuf.put("even more");
		return textbuf[].idup;
	}
	
	auto s = cat("hello", "betty");
	assert(s == "hellobettyeven more");
}

/*********************************
 * This is a slightly simpler way to create a DataBuffer instance
 * that uses type deduction.
 * Params:
 *      tmpbuf = the initial buffer to use
 * Returns:
 *      an instance of DataBuffer
 * Example:
---
ubyte[10] tmpbuf = void;
auto sb = dataBuffer(tmpbuf);
scope(exit) sp.free();
---
 */

auto dataBuffer(T)(T[] tmpbuf)
{
	return DataBuffer!T(tmpbuf);
}

unittest
{
	ubyte[10] tmpbuf = void;
	auto sb = dataBuffer(tmpbuf);
	scope(exit) sb.free();
}

unittest
{
	DataBuffer!(int*) b;
	int*[] s;
	b.put(s);
	
	DataBuffer!char c;
	string s1;
	char[] s2;
	c.put(s1);
	c.put(s2);
}

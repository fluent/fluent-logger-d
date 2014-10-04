# build mode: 32bit or 64bit
MODEL ?= $(shell getconf LONG_BIT)
DMD ?= dmd

LIB    = libfluentlogger.a
DFLAGS = -Isrc -m$(MODEL) -w -d -property

ifeq ($(BUILD),debug)
	DFLAGS += -g -debug
else
	DFLAGS += -O -release -nofloat -inline -noboundscheck
endif

NAMES   = fluent/logger
FILES   = $(addsuffix .d, $(NAMES))
SRCS    = $(addprefix src/, $(FILES))

# DDoc
DOCS      = $(addsuffix .html, logger)
DOCDIR    = html
CANDYDOC  = $(addprefix html/candydoc/, candy.ddoc modules.ddoc)
DDOCFLAGS = -Dd$(DOCDIR) -c -o- -Isrc $(CANDYDOC)

target: $(LIB)

$(LIB):
	$(DMD) $(DFLAGS) -lib -of$(LIB) $(SRCS)

doc:
	$(DMD) $(DDOCFLAGS) $(SRCS)

clean:
	rm $(addprefix $(DOCDIR)/, $(DOCS)) $(LIB)

MAIN_FILE = "empty_fluent_logger_unittest.d"

unittest:
	echo 'import fluent.logger; void main(){}' > $(MAIN_FILE)
	$(DMD) $(DFLAGS) -unittest -of$(LIB) $(SRCS) -run $(MAIN_FILE)
	rm $(MAIN_FILE)

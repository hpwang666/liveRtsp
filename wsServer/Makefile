include ../Makefile.pub

DEFS =
CFLAGS := -Wall $(DEFS) -I. -O0 -g
CFLAGS += -I../../libevent/include -I./ -I../net/protocol -I../net/reactor -I../util/include -I../
CXXFLAGS:=$(CFLAGS)
CCFLAGS:=$(CFLAGS)
LIBPATH := -L../../libevent/lib
LIBS :=  ../util/lib/libutil.a -lpthread -levent




##### End of variables to change
.PHONY :prepare all clean install

TARGET = wsServer_bin
ALL = $(TARGET)
all: prepare $(ALL)

SOURCES =  $(wildcard *.c) 

#change .cpp files  to .o files
OBJFILES = $(SOURCES:%.c=obj/%.o)

obj/%.o:%.c 
	$(COMPILE_CC)
	
$(TARGET):	$(OBJFILES)  
	$(call ASSEMBLE_EXTRA,CC)
prepare:
	@echo "preparing..."
	@if ! [ -d obj ]; then mkdir obj; fi;
clean:
	-rm -rf *.o $(ALL) *~ obj/* obj
install:
	install $(TARGET) $(INSTALL_DIR)

##### Any additional, platform-specific rules come here:

XEN_ROOT = $(CURDIR)/../../../../..
include $(XEN_ROOT)/tools/Rules.mk

GO ?= go

TESTS = dominfo freememory maxcpu onlinecpu physinfo versioninfo
CBINARIES = $(TESTS:%=%-c)
GOBINARIES = $(TESTS:%=%-go)

all: build

test: clean build
	for test in $(TESTS) ; do \
		./$$test-c >> c.output ; \
	        ./$$test-go >> go.output ; \
		if cmp -s "c.output" "go.output"; then\
			echo "$$test PASSED";\
		else \
			echo "$$test FAILED";\
		fi ; \
	done

build: $(CBINARIES) $(GOBINARIES)

%-c: %.c
	gcc $(CFLAGS_libxenlight) -o $@ $< $(LDLIBS_libxenlight)

%-go: %.go
	GOPATH=$(XEN_ROOT)/tools/golang $(GO) build -o $@ $<

clean:
	rm -f *-c
	rm -f *-go
	rm -f *.output

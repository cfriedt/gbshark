# MIT License
#
# Copyright (c) 2018 Christopher Friedt
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

.PHONY: all clean check gtest gcov clangtidy

CXX ?= $(CROSS_COMPILE)g++
#CXX := clang++

CPPFLAGS :=
CXXFLAGS :=
LDFLAGS :=
LDLIBS :=
GCOVFLAGS :=
GCOVRFLAGS :=
CTIDYFLAGS :=

CXXFLAGS += -Wall -Werror -Wextra -g -O0 -std=c++14

CPPFLAGS += -Ipriv

# gcov
CXXFLAGS += -fprofile-arcs -ftest-coverage
GCOVFLAGS += -r
GCOVRFLAGS += -r $(shell pwd) -e '.*-test.cpp' -e 'util/'

# gtest flags
CPPFLAGS += $(shell pkg-config --cflags gtest)
LDLIBS += $(shell pkg-config --libs gtest_main)

# wireshark
CPPFLAGS += $(shell pkg-config --cflags wireshark)
LDLIBS += $(shell pkg-config --libs wireshark)

CPPFLAGS += -Iutil

CTIDYCHECKS :=
CTIDYCHECKS += clang-analyzer-core*
CTIDYCHECKS += clang-analyzer-security*
CTIDYCHECKS += clang-analyzer-unix*
CTIDYCHECKS += clang-analyzer-valist*
CTIDYCHECKS += clang-analyzer-optin.cplusplus*
CTIDYCHECKS += clang-analyzer-optin.portability*
CTIDYCHECKS += clang-analyzer-nullability*
CTIDYCHECKS += clang-analyzer-deadcode*
CTIDYCHECKS += clang-analyzer-cplusplus*
NOTHING :=
SPACE := $(NOTHING) $(NOTHING)
COMMA := ,
CTIDYCHECKLIST := $(subst $(SPACE),$(COMMA),$(strip $(CTIDYCHECKS)))

CTIDYFLAGS += -header-filter='.*'
CTIDYFLAGS += -checks='$(CTIDYCHECKLIST)'
CTIDYFLAGS += -warnings-as-errors='$(CTIDYCHECKLIST)'

CPPSRC = $(shell ls *-test.cpp 2>/dev/null)

EXE = $(CPPSRC:.cpp=)

all: $(EXE)

%-test: %-test.cpp %.cpp Makefile
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(EXE) *-test *.gcno *.gcov *.gcda *.clangtidy

check:
	$(MAKE) gtest
	$(MAKE) gcov
	$(MAKE) clangtidy

gtest: $(EXE)
	NTEST=0; \
	NPASS=0; \
	if [ -z "$(strip $(EXE))" ]; then \
		exit 0; \
	fi; \
	for i in $(EXE); do \
		./$$i; \
		if [ $$? -eq 0 ]; then \
			NPASS=$$((NPASS+1)); \
		fi; \
		NTEST=$$((NTEST+1)); \
	done; \
	if [ $$NPASS -eq $$NTEST ]; then \
		exit 0; \
	else \
		exit 1; \
	fi

gcov: $(EXE)
	if [ -z "$(strip $(EXE))" ]; then \
		exit 0; \
	fi; \
	for i in $(EXE); do \
		gcov $(GCOVFLAGS) $${i}.cpp &> /dev/null; \
	done; \
	gcovr $(GCOVRFLAGS); \
	PCNT=`gcovr $(GCOVRFLAGS) | grep "^TOTAL" | tail -n 1 | awk '{print $$4}' | sed -e 's|%||'`; \
	if [ $${PCNT} -lt 90 ]; then \
		exit 1; \
	fi

%.clangtidy: %.cpp
	clang-tidy $(CTIDYFLAGS) $< -- $(CPPFLAGS) $(CXXFLAGS) &> $@ || cat $@

clangtidy: $(addsuffix .clangtidy,$(EXE))

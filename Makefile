CC=cc
CFLAGS=-I. -Iminilzo-2.09 -Wall -Wextra -pedantic
LDFLAGS=

BUILDDIR = build
EXECUTABLE = $(BUILDDIR)/desafenet

CSRC += desafenet.c
CSRC += minilzo-2.09/minilzo.c

COBJ += $(patsubst %, $(BUILDDIR)/%,$(CSRC:.c=.o))

all: $(EXECUTABLE) $(BUILDDIR)/.sentinel

$(COBJ) : $(BUILDDIR)/%.o : %.c $(BUILDDIR)/.sentinel
	@echo COMPILING: $<
	$(CC) -c $(CFLAGS) $< -o $@

$(EXECUTABLE):  $(COBJ)
	@echo LINKING: $@
	$(CC) $(COBJ) $(LDFLAGS) -o $@

.PRECIOUS: %/.sentinel
%/.sentinel:
	@mkdir -p ${@D}
	@mkdir -p $(BUILDDIR)/minilzo-2.09
	@touch $@

clean:
	@echo CLEANING UP:
	rm -rf $(BUILDDIR)

# src/pl/cpro/Makefile

MODULE_big = cpro
OBJS = parser.o scanner.o ast.o cpro.o
PG_CPPFLAGS = -I$(libpq_srcdir)
SHLIB_LINK = $(libpq)

EXTENSION = cpro
DATA = cpro--1.0.sql cpro.control
PGFILEDESC = "cpro - An Extension for Monitering CPU and Processes"

#regression test
REGRESS = cpro
#REGRESS_OPTS = --port=8432

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = pl/cpro
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

parser.o: scanner.c

scanner.c: scanner.l
	flex -d --header-file=scanner.h --outfile=$@ $^

parser.c: parser.y
	bison -Wno-deprecated -vd $^ -o $@

.PHONY:clean clean-cpro

clean: clean-cpro

clean-cpro:
	rm -rf parser.[cho] scanner.[cho] *.output

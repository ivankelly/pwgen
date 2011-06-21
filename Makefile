PWGEN_VERSION=2.05

srcdir = .
top_srcdir = .

top_builddir = .
my_dir = .
prefix = /usr/local
mandir = ${prefix}/man
INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

WALL_OPTS = -Wall -Wnested-externs -Wstrict-prototypes -Wmissing-prototypes \
	-Wshadow -Wwrite-strings -Wpointer-arith -Wcast-qual -Wcast-align \
	-pedantic
CC = gcc
DEFS = -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DHAVE_DRAND48=1 -DHAVE_GETOPT_LONG=1 -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -DHAVE_GETOPT_H=1 
CFLAGS = -g -O2 $(WALL_OPTS)
CPPFLAGS = 
ALL_CFLAGS = $(CPPFLAGS) $(DEFS) $(USE_WFLAGS) $(CFLAGS) $(XTRA_CFLAGS) 
LDFLAGS = 
RM = /bin/rm
MV = /bin/mv
SED = /bin/sed
PERL = /usr/bin/perl
TAR = tar

all:: pwgen

.c.o:
	$(CC) -c $(ALL_CFLAGS) $< -o $@

OBJS= pwgen.o pw_phonemes.o pw_rand.o randnum.o sha1.o sha1num.o

SRCS= pwgen.c pw_phonemes.c pw_rand.c randnum.c sha1.c sha1num.c


pwgen: $(OBJS)
	$(CC) $(LDFLAGS) -o pwgen $(OBJS)

install: pwgen pwgen.1
	mkdir -p $(DESTDIR)$(prefix)/bin $(DESTDIR)$(mandir)/man1
	$(INSTALL_PROGRAM) pwgen $(DESTDIR)$(prefix)/bin/pwgen
	$(INSTALL_DATA) $(srcdir)/pwgen.1 $(DESTDIR)$(mandir)/man1/pwgen.1

clean:
	$(RM) -f $(OBJS) pwgen *~

distclean: clean
	$(RM) -rf config.status config.log config.cache Makefile \
		$(srcdir)/Makefile.in.old $(srcdir)/.exclude-file \
		$(srcdir)/autom4te.cache

#
# Build source tar ball...
#

SRCROOT = pwgen-$(PWGEN_VERSION)

$(srcdir)/.exclude-file:
	a=$(SRCROOT); \
	(cd $(srcdir)/.. && find src \( -name \*~ -o -name \*.orig \
		-o -name CVS -o -name \*.rej \
		-o -name TAGS -o -name \*.old -o -name \*.gmo \
		-o -name changed-files -o -name .#\* \) \
		-print) | sed -e "s/src/$$a/" > $(srcdir)/.exclude-file
	echo "$(SRCROOT)/build" >> $(srcdir)/.exclude-file
	echo "$(SRCROOT)/rpm.log" >> $(srcdir)/.exclude-file
	echo "$(SRCROOT)/config.log" >> $(srcdir)/.exclude-file
	echo "$(SRCROOT)/config.status" >> $(srcdir)/.exclude-file
	echo "$(SRCROOT)/config.cache" >> $(srcdir)/.exclude-file
	echo "$(SRCROOT)/TODO" >> $(srcdir)/.exclude-file
	echo "$(SRCROOT)/.exclude-file" >> $(srcdir)/.exclude-file
		>> $(srcdir)/.exclude-file

source_tar_file: $(srcdir)/.exclude-file
	cd $(srcdir)/.. && a=$(SRCROOT); rm -f $$a ; ln -sf src $$a ; \
		$(TAR) -c -h -v -f - \
			-X $$a/.exclude-file $$a | \
		gzip -9 > pwgen-$(PWGEN_VERSION).tar.gz
	rm -f $(srcdir)/.exclude-file
#
# Autoconf magic...
#

$(top_builddir)/config.status: $(top_srcdir)/configure
	cd $(top_builddir); ./config.status --recheck

Makefile: $(srcdir)/Makefile.in $(DEP_MAKEFILE) $(top_builddir)/config.status
	cd $(top_builddir); CONFIG_FILES=$(my_dir)/Makefile ./config.status

$(top_srcdir)/configure: $(top_srcdir)/configure.in
	cd $(top_srcdir) && autoconf

#
# Make depend magic...
#

.depend: Makefile $(SRCS) $(top_srcdir)/depfix.sed $(top_srcdir)/wordwrap.pl
	if test -n "$(SRCS)" ; then \
		$(CC) -M $(ALL_CFLAGS) $(SRCS) | \
			$(SED) -f $(top_srcdir)/depfix.sed \
			    -e 's; $(srcdir)/; $$(srcdir)/;g' \
			    -e 's; $(top_srcdir)/; $$(top_srcdir)/;g' \
			    -e 's; $(top_builddir)/; $$(top_builddir)/;g' \
			    -e 's; \./; ;g' \
			    -e '/^ *\\$$/d' | \
			$(PERL) $(top_srcdir)/wordwrap.pl > .depend; \
	else :; fi

depend:: .depend
	if test -n "$(SRCS)" ; then \
		sed -e '/^# +++ Dependency line eater +++/,$$d' \
			< $(srcdir)/Makefile.in | cat - .depend \
			> $(srcdir)/Makefile.in.new; \
	if cmp -s $(srcdir)/Makefile.in $(srcdir)/Makefile.in.new ; then \
		$(RM) $(srcdir)/Makefile.in.new ; \
	else \
		$(MV) $(srcdir)/Makefile.in $(srcdir)/Makefile.in.old; \
		$(MV) $(srcdir)/Makefile.in.new $(srcdir)/Makefile.in; \
	fi ; else :; fi

# +++ Dependency line eater +++
# 
# Makefile dependencies follow.  This must be the last section in
# the Makefile.in file
#
pwgen.o: pwgen.c pwgen.h
pw_phonemes.o: pw_phonemes.c pwgen.h
pw_rand.o: pw_rand.c pwgen.h
randnum.o: randnum.c pwgen.h
sha1.o: sha1.c sha1.h 
sha1num.o: sha1num.c sha1.h pwgen.h

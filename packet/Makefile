# dlls/packet/Makefile.  Generated from Makefile.in by configure.      -*-Makefile-*-

prefix          = /usr/local
exec_prefix     = ${prefix}
bindir          = ${exec_prefix}/bin
libdir          = ${exec_prefix}/lib
datarootdir     = ${prefix}/share
datadir         = ${datarootdir}
infodir         = ${datarootdir}/info
mandir          = ${datarootdir}/man
fontdir         = $(datadir)/wine/fonts
includedir      = ${prefix}/include/wine
dlldir          = ${exec_prefix}/lib/wine
fakedlldir      = $(dlldir)/fakedlls
top_srcdir      = ../..
top_builddir    = ../..
srcdir          = .

SHELL           = /bin/sh
RM              = rm -f
MV              = mv
CC              = gcc
CROSSCC         = 
CFLAGS          = -g -O0
CPPFLAGS        = -I/usr/include/freetype2   
EXTRACFLAGS     = -Wall -pipe -fno-strict-aliasing -Wdeclaration-after-statement -Wempty-body -Wignored-qualifiers -Wstrict-prototypes -Wtype-limits -Wunused-but-set-parameter -Wwrite-strings -fno-omit-frame-pointer -Wpointer-arith -Wlogical-op
TARGETFLAGS     = 
LIBS            = 
BISON           = bison
FLEX            = flex
EXEEXT          = 
OBJEXT          = o
LIBEXT          = so
DLLEXT          = .so
FAKEEXT         = $(DLLEXT:.so=.fake)
TOOLSEXT        = 
IMPLIBEXT       = def
DLLTOOL         = 
DLLWRAP         = 
AR              = ar
ARFLAGS         = rc
RANLIB          = ranlib
LN_S            = ln -s
TOOLSDIR        = $(top_builddir)
LDFLAGS         = -liphlpapi
PRELINK         = /usr/sbin/prelink
LINT            = 
LINTFLAGS       = 
FONTFORGE       = fontforge
RSVG            = false
CONVERT         = convert
ICOTOOL         = icotool
MSGFMT          = msgfmt
CROSSTARGET     = 
LINGUAS         = ar bg ca cs da de el en en_US eo es fa fi fr he hi hu it ja ko lt ml nb_NO nl or pa pl pt_BR pt_PT rm ro ru sk sl sr_RS@cyrillic sr_RS@latin sv te th tr uk wa zh_CN zh_TW
ALL_MO_FILES    = $(LINGUAS:%=../../po/%.mo)
PORCFLAGS       = --po-dir=$(top_builddir)/po
CROSSAR         = $(CROSSTARGET)-ar
CROSSRANLIB     = $(CROSSTARGET)-ranlib
MKINSTALLDIRS   = $(top_srcdir)/tools/mkinstalldirs -m 755
WINAPI_CHECK    = $(top_srcdir)/tools/winapi/winapi_check
BUILDIMAGE      = $(top_srcdir)/tools/buildimage
C2MAN           = $(top_srcdir)/tools/c2man.pl
RUNTEST         = $(top_srcdir)/tools/runtest
MAKECTESTS      = $(TOOLSDIR)/tools/make_ctests$(TOOLSEXT)
MAKEXFTMPL      = $(TOOLSDIR)/tools/make_xftmpl$(TOOLSEXT)
MAKEDEP         = $(TOOLSDIR)/tools/makedep$(TOOLSEXT)
RELPATH         = $(TOOLSDIR)/tools/relpath$(TOOLSEXT)
SFNT2FNT        = $(TOOLSDIR)/tools/sfnt2fnt$(TOOLSEXT)
WIDL            = $(TOOLSDIR)/tools/widl/widl$(TOOLSEXT)
WINEBUILD       = $(TOOLSDIR)/tools/winebuild/winebuild$(TOOLSEXT)
WMC             = $(TOOLSDIR)/tools/wmc/wmc$(TOOLSEXT)
WRC             = $(TOOLSDIR)/tools/wrc/wrc$(TOOLSEXT)
LIBPORT         = $(top_builddir)/libs/port/libwine_port.a
LIBWPP          = $(top_builddir)/libs/wpp/libwpp.a
LIBWINE         = -L$(top_builddir)/libs/wine -lwine
WINEGCC         = $(TOOLSDIR)/tools/winegcc/winegcc $(TARGETFLAGS) -B$(TOOLSDIR)/tools/winebuild --sysroot=$(top_builddir) -fasynchronous-unwind-tables
CROSSWINEGCC    = $(TOOLSDIR)/tools/winegcc/winegcc $(CROSSTARGET:%=-b %) -B$(TOOLSDIR)/tools/winebuild --sysroot=$(top_builddir) --lib-suffix=.cross.a
LDPATH          = LD_LIBRARY_PATH="$(TOOLSDIR)/libs/wine:$$LD_LIBRARY_PATH"
LDRPATH_INSTALL = -Wl,--rpath,\$$ORIGIN/`$(RELPATH) $(bindir) $(libdir)` -Wl,--enable-new-dtags
LDRPATH_LOCAL   = -Wl,--rpath,\$$ORIGIN/$(top_builddir)/libs/wine
INSTALL         = /usr/bin/install -c $(INSTALL_FLAGS)
INSTALL_PROGRAM = ${INSTALL} $(INSTALL_PROGRAM_FLAGS)
INSTALL_SCRIPT  = ${INSTALL} $(INSTALL_SCRIPT_FLAGS)
INSTALL_DATA    = ${INSTALL} -m 644 $(INSTALL_DATA_FLAGS)
prog_manext     = 1
api_manext      = 3w
conf_manext     = 5


all:

# End of common header
# Generated from packet.dll by winedump.
MODULE    = packet.dll


C_SRCS = \
	packet_main.c

# Global rules for building dlls     -*-Makefile-*-
#
# Each individual makefile should define the following variables:
# MODULE       : name of the main module being built
# EXTRALIBS    : extra libraries to link in (optional)
#
# plus all variables required by the global Make.rules.in
#

DLLFLAGS    = -D_REENTRANT -fPIC
DEFS        = -D__WINESRC__ $(EXTRADEFS)
BASEMODULE  = $(MODULE:%.dll=%)
MAINSPEC    = $(BASEMODULE).spec
ALL_LIBS    = $(LIBPORT) $(EXTRALIBS) $(LDFLAGS) $(LIBS)
IDL_TLB_RES = $(IDL_TLB_SRCS:.idl=_t.res)
IMPLIB_OBJS = $(IMPLIB_SRCS:.c=.o)
IMPLIBFLAGS = $(TARGETFLAGS) $(EXTRAIMPLIBFLAGS)
IMPORTLIBFILE = $(IMPORTLIB:%=lib%.def)
STATICIMPLIB  = $(IMPORTLIBFILE:.def=.def.a)
INSTALLDIRS = $(DESTDIR)$(dlldir) $(DESTDIR)$(fakedlldir) $(DESTDIR)$(datadir)/wine

# Global rules shared by all makefiles     -*-Makefile-*-
#
# Each individual makefile may define the following variables:
# C_SRCS       : C sources for the module
# RC_SRCS      : resource source files
# EXTRA_SRCS   : extra source files for make depend
# EXTRA_OBJS   : extra object files
# IMPORTS      : dlls to import
# DELAYIMPORTS : dlls to import in delayed mode
# EXTRASUBDIRS : subdirectories that do not contain a Makefile
# MODCFLAGS    : extra CFLAGS for this module

# First some useful definitions

LDSHARED     = $(CC) -shared $(SONAME:%=-Wl,-soname,%) $(VERSCRIPT:%=-Wl,--version-script=%)
INCLUDES     = -I$(srcdir) -I. -I$(top_srcdir)/include -I$(top_builddir)/include $(EXTRAINCL)
ALLCFLAGS    = $(INCLUDES) $(DEFS) $(DLLFLAGS) $(EXTRACFLAGS) $(CPPFLAGS) $(CFLAGS) $(MODCFLAGS)
ALLLINTFLAGS = $(INCLUDES) $(DEFS) $(LINTFLAGS)
IDLFLAGS     = $(INCLUDES) $(DEFS) $(EXTRAIDLFLAGS)
RCFLAGS      = --nostdinc $(PORCFLAGS) $(TARGETFLAGS) $(INCLUDES) $(DEFS) $(EXTRARCFLAGS)

IDL_GEN_C_SRCS  = $(IDL_C_SRCS:.idl=_c.c) $(IDL_I_SRCS:.idl=_i.c) \
                  $(IDL_P_SRCS:.idl=_p.c) $(IDL_S_SRCS:.idl=_s.c)
IDL_GEN_HEADERS = $(IDL_H_SRCS:.idl=.h) $(IDL_C_SRCS:.idl=.h) $(IDL_I_SRCS:.idl=.h) \
                  $(IDL_P_SRCS:.idl=.h) $(IDL_S_SRCS:.idl=.h)

CLEAN_FILES   = *.o *.a *.so *.mo *.ln *.res *.fake *.$(LIBEXT) \\\#*\\\# *~ *% .\\\#* *.bak *.orig *.rej *.flc core
CLEAN_TARGETS = $(IDL_GEN_C_SRCS) $(IDL_GEN_HEADERS) $(IDL_TLB_SRCS:.idl=.tlb) $(IDL_P_SRCS:%=dlldata.c) \
                $(BISON_SRCS:.y=.tab.c) $(BISON_SRCS:.y=.tab.h) $(LEX_SRCS:.l=.yy.c) \
                $(PO_SRCS:%=rsrc.pot) $(MC_SRCS:%=msg.pot) $(XTEMPLATE_SRCS:.x=.h)

OBJS = $(C_SRCS:.c=.o) $(BISON_SRCS:.y=.tab.o) $(LEX_SRCS:.l=.yy.o) $(IDL_GEN_C_SRCS:.c=.o) \
       $(IDL_R_SRCS:.idl=_r.res) $(IDL_TLB_RES) $(RC_SRCS:.rc=.res) $(MC_SRCS:.mc=.res) $(EXTRA_OBJS)

CROSSOBJS = $(OBJS:.o=.cross.o)
LINTS  = $(C_SRCS:.c=.ln)

filter: dummy
	@$(top_srcdir)/tools/winapi/make_filter --make $(MAKE) all

.PHONY: all filter

# Implicit rules

.SUFFIXES: .mc .rc .res .idl .tlb .h .y .l .tab.c .tab.h .yy.c .ok .man.in .man _c.c _i.c _p.c _s.c _r.res _t.res .cross.o .po .mo # .sfd .ttf .svg .ico .bmp

.c.o:
	$(CC) -c $(ALLCFLAGS) -o $@ $<

.c.cross.o:
	$(CROSSCC) -c $(INCLUDES) $(DEFS) -DWINE_CROSSTEST $(CPPFLAGS) $(CFLAGS) -o $@ $<

.y.tab.c:
	$(BISON) $(BISONFLAGS) -p $*_ -o $@ $<

.y.tab.h:
	$(BISON) $(BISONFLAGS) -p $*_ -o $*.tab.c -d $<

.l.yy.c:
	$(FLEX) $(LEXFLAGS) -o$@ $<

.mc.res:
	$(LDPATH) $(WMC) -U -O res -P $(top_srcdir)/po -o $@ $<

.rc.res:
	$(LDPATH) $(WRC) $(RCFLAGS) -o $@ $<

.idl.h:
	$(WIDL) $(IDLFLAGS) -h -o $@ $<

.idl_c.c:
	$(WIDL) $(IDLFLAGS) -c -o $@ $<

.idl_i.c:
	$(WIDL) $(IDLFLAGS) -u -o $@ $<

.idl_p.c:
	$(WIDL) $(IDLFLAGS) -p -o $@ $<

.idl_r.res:
	$(WIDL) $(IDLFLAGS) -r -o $@ $<

.idl_s.c:
	$(WIDL) $(IDLFLAGS) -s -o $@ $<

.idl.tlb:
	$(WIDL) $(TARGETFLAGS) $(IDLFLAGS) -t -o $@ $<

.idl_t.res:
	$(WIDL) $(TARGETFLAGS) $(IDLFLAGS) -t -o $@ $<

.c.ln:
	$(LINT) -c $(ALLLINTFLAGS) $< || ( $(RM) $@ && exit 1 )

.c.ok:
	$(RUNTEST) $(RUNTESTFLAGS) $< && touch $@

.sfd.ttf:
	$(FONTFORGE) -script $(top_srcdir)/fonts/genttf.ff $< $@

.man.in.man:
	LC_ALL=C sed -e 's,@bindir\@,$(bindir),g' -e 's,@dlldir\@,$(dlldir),g' -e 's,@PACKAGE_STRING\@,Wine 1.5.3,g' $< >$@ || ($(RM) $@ && false)

.svg.ico:
	CONVERT="$(CONVERT)" ICOTOOL="$(ICOTOOL)" RSVG="$(RSVG)" $(BUILDIMAGE) $< $@

.svg.bmp:
	CONVERT="$(CONVERT)" ICOTOOL="$(ICOTOOL)" RSVG="$(RSVG)" $(BUILDIMAGE) $< $@

.po.mo:
	$(MSGFMT) -o $@ $<

# Rules for IDL files

dlldata.c: $(WIDL) Makefile.in
	$(WIDL) $(IDLFLAGS) --dlldata-only -o $@ $(IDL_P_SRCS)

# Rule for linting

$(MODULE).ln : $(LINTS)
	if test "$(LINTS)" ; \
	then \
		$(LINT) $(ALLLINTFLAGS) -o$(MODULE) $(LINTS) ; \
	        $(MV) llib-l$(MODULE).ln $(MODULE).ln ; \
	else \
		$(LINT) $(ALLLINTFLAGS) -C$(MODULE) /dev/null ; \
	fi

lint:: $(MODULE).ln

# Rules for Windows API checking

winapi_check:: dummy
	$(WINAPI_CHECK) $(WINAPI_CHECK_FLAGS) $(WINAPI_CHECK_EXTRA_FLAGS) .

.PHONY: winapi_check

# Rules for dependencies

DEPEND_SRCS = $(C_SRCS) $(RC_SRCS) $(MC_SRCS) \
              $(IDL_H_SRCS) $(IDL_C_SRCS) $(IDL_I_SRCS) $(IDL_P_SRCS) $(IDL_S_SRCS) \
              $(IDL_GEN_C_SRCS) $(IDL_R_SRCS:.idl=_r.res) $(IDL_TLB_SRCS) $(IDL_TLB_SRCS:.idl=.tlb) \
              $(BISON_SRCS) $(LEX_SRCS) $(EXTRA_SRCS)

depend: dummy
	$(MAKEDEP) $(MAKEDEPFLAGS) -C$(srcdir) -S$(top_srcdir) -T$(top_builddir) $(EXTRAINCL) $(DEPEND_SRCS)

.PHONY: depend

# Rules for man pages

MANPAGES = $(MANPAGE) $(EXTRA_MANPAGES)

all: $(MANPAGES)

install-man-pages:: $(MANPAGE) $(DESTDIR)$(mandir)/man$(prog_manext)
	$(INSTALL_DATA) $(MANPAGE) $(DESTDIR)$(mandir)/man$(prog_manext)/$(MANPAGE:.man=).$(prog_manext)

uninstall-man-pages::
	$(RM) $(DESTDIR)$(mandir)/man$(prog_manext)/$(MANPAGE:.man=).$(prog_manext)

install::  $(MANPAGE:%=install-man-pages)
uninstall::  $(MANPAGE:%=uninstall-man-pages)

# Rules for cleaning

$(EXTRASUBDIRS:%=%/__clean__): dummy
	-cd `dirname $@` && $(RM) $(CLEAN_FILES)

clean:: $(EXTRASUBDIRS:%=%/__clean__)
	$(RM) $(CLEAN_FILES) $(CLEAN_TARGETS) $(PROGRAMS) $(MANPAGES)

.PHONY: clean $(EXTRASUBDIRS:%=%/__clean__)

# Rules for installing

$(INSTALLDIRS):
	$(MKINSTALLDIRS) $@

install install-lib install-dev uninstall::

.PHONY: install install-lib install-dev uninstall

# Rules for resources

rsrc.pot: $(WRC)
	$(LDPATH) $(WRC) $(RCFLAGS) -O pot -o $@ $(PO_SRCS)

msg.pot: $(WMC)
	$(LDPATH) $(WMC) -O pot -o $@ $(MC_SRCS)

$(MC_SRCS:.mc=.res): $(WMC) $(ALL_MO_FILES)
$(RC_SRCS:.rc=.res): $(WRC)
$(PO_SRCS:.rc=.res): $(ALL_MO_FILES)

# Misc. rules

$(IDL_GEN_HEADERS) $(IDL_GEN_C_SRCS) $(IDL_TLB_SRCS:.idl=.tlb) $(IDL_TLB_RES) $(IDL_R_SRCS:.idl=_r.res): $(WIDL)

dummy:

.PHONY: dummy

# End of global rules

all: $(MODULE)$(DLLEXT) $(MODULE)$(FAKEEXT)

$(MODULE) $(MODULE).so $(MODULE).fake: $(MAINSPEC) $(OBJS) Makefile.in
	$(WINEGCC) -shared $(srcdir)/$(MAINSPEC) $(OBJS) $(EXTRADLLFLAGS) -o $@ $(DELAYIMPORTS:%=-l%) $(IMPORTS:%=-l%) $(DELAYIMPORTS:%=-Wb,-d%) $(ALL_LIBS)

# Rules for import libraries

IMPLIB_CROSSOBJS = $(IMPLIB_OBJS:.o=.cross.o)

.PHONY: $(IMPLIB_SRCS:%=__static_implib__%)

all: $(IMPORTLIBFILE) $(IMPLIB_SRCS:%=__static_implib__%) # $(IMPORTLIB:%=lib%.cross.a)

$(IMPLIB_SRCS:%=__static_implib__%): $(STATICIMPLIB)

$(IMPORTLIB:%=lib%.def): $(MAINSPEC)
	$(WINEBUILD) $(IMPLIBFLAGS) -w --def -o $@ --export $(srcdir)/$(MAINSPEC)

$(IMPORTLIB:%=lib%.def.a): $(IMPLIB_OBJS)
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(IMPLIB_OBJS)
	$(RANLIB) $@

$(IMPORTLIB:%=lib%.a): $(MAINSPEC) $(IMPLIB_OBJS)
	$(WINEBUILD) $(IMPLIBFLAGS) -w --implib -o $@ --export $(srcdir)/$(MAINSPEC) $(IMPLIB_OBJS)

$(IMPORTLIB:%=lib%.cross.a): $(MAINSPEC) $(IMPLIB_CROSSOBJS)
	$(WINEBUILD) $(IMPLIBFLAGS) $(CROSSTARGET:%=-b %) -w --implib -o $@ --export $(srcdir)/$(MAINSPEC) $(IMPLIB_CROSSOBJS)

# Rules for auto documentation

manpages:: $(C_SRCS) dummy
	$(C2MAN) -o $(top_builddir)/documentation/man$(api_manext) -R$(top_builddir) -C$(srcdir) -S$(api_manext) $(INCLUDES) $(MAINSPEC:%=-w %) $(C_SRCS)

htmlpages:: $(C_SRCS) dummy
	$(C2MAN) -o $(top_builddir)/documentation/html -R$(top_builddir) -C$(srcdir) $(INCLUDES) -Th $(MAINSPEC:%=-w %) $(C_SRCS)

sgmlpages:: $(C_SRCS) dummy
	$(C2MAN) -o $(top_builddir)/documentation/api-guide -R$(top_builddir) -C$(srcdir) $(INCLUDES) -Ts $(MAINSPEC:%=-w %) $(C_SRCS)

xmlpages:: $(C_SRCS) dummy
	$(C2MAN) -o $(top_builddir)/documentation/api-guide-xml -R$(top_builddir) -C$(srcdir) $(INCLUDES) -Tx $(MAINSPEC:%=-w %) $(C_SRCS)

# Rules for installation

.PHONY: install_dll install_dll.so install_dll.fake

install_dll: $(MODULE) $(DESTDIR)$(dlldir) dummy
	$(INSTALL_PROGRAM) $(MODULE) $(DESTDIR)$(dlldir)/$(MODULE)

install_dll.so: $(MODULE).so $(DESTDIR)$(dlldir) dummy
	$(INSTALL_PROGRAM) $(MODULE).so $(DESTDIR)$(dlldir)/$(MODULE).so

install_dll.fake: $(MODULE).fake $(DESTDIR)$(fakedlldir) dummy
	$(INSTALL_DATA) $(MODULE).fake $(DESTDIR)$(fakedlldir)/$(MODULE)

install install-lib:: install_dll$(DLLEXT) install_dll$(FAKEEXT)

uninstall::
	$(RM) $(DESTDIR)$(dlldir)/$(MODULE)$(DLLEXT) $(DESTDIR)$(fakedlldir)/$(MODULE)

# Misc. rules

clean::
	$(RM) $(IMPORTLIBFILE)

# End of global dll rules


### Dependencies
packet_main.o : packet_main.c ../../include/windef.h \
 ../../include/winnt.h ../../include/basetsd.h ../../include/guiddef.h \
 ../../include/winnt.rh ../../include/pshpack2.h \
 ../../include/poppack.h ../../include/pshpack8.h \
 ../../include/pshpack4.h ../../include/winbase.h \
 ../../include/winerror.h ../../include/wine/debug.h packet32.h \
 sockstorage.h bittypes.h pcap-stdinc.h ../../include/winsock2.h \
 ../../include/winsock.h ../../include/windows.h \
 ../../include/winresrc.h ../../include/winuser.rh \
 ../../include/commctrl.rh ../../include/dde.rh ../../include/dlgs.h \
 ../../include/winver.h ../../include/verrsrc.h ../../include/excpt.h \
 ../../include/wingdi.h ../../include/winuser.h ../../include/winnls.h \
 ../../include/wincon.h ../../include/winreg.h ../../include/reason.h \
 ../../include/winnetwk.h ../../include/cderr.h ../../include/dde.h \
 ../../include/ddeml.h ../../include/lzexpand.h \
 ../../include/mmsystem.h ../../include/pshpack1.h \
 ../../include/nb30.h ../../include/rpc.h ../../include/rpcdce.h \
 ../../include/rpcdcep.h ../../include/rpcnterr.h \
 ../../include/rpcasync.h ../../include/shellapi.h \
 ../../include/winperf.h ../../include/wincrypt.h \
 ../../include/bcrypt.h ../../include/winscard.h \
 ../../include/wtypes.h ../../include/rpcndr.h ../../include/rpcsal.h \
 ../../include/winioctl.h ../../include/winsmcrd.h \
 ../../include/scarderr.h ../../include/winspool.h \
 ../../include/ole2.h ../../include/objbase.h ../../include/unknwn.h \
 ../../include/objidl.h ../../include/cguid.h ../../include/urlmon.h \
 ../../include/oleidl.h ../../include/servprov.h ../../include/msxml.h \
 ../../include/oaidl.h ../../include/propidl.h ../../include/oleauto.h \
 ../../include/commdlg.h ../../include/prsht.h ../../include/winsvc.h \
 ../../include/mcx.h ../../include/imm.h ../../include/inaddr.h \
 ../../include/ws2def.h ../../include/iphlpapi.h \
 ../../include/iprtrmib.h ../../include/mprapi.h \
 ../../include/lmcons.h ../../include/ras.h ../../include/in6addr.h \
 ../../include/ipifcons.h ../../include/ipmib.h ../../include/ifmib.h \
 ../../include/ifdef.h ../../include/nldef.h ../../include/tcpmib.h \
 ../../include/udpmib.h ../../include/ipexport.h \
 ../../include/iptypes.h

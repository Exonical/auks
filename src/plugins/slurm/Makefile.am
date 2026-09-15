EXTRA_DIST		=	slurm-spank-auks.conf auks.so.8

if HAVE_SLURM

man8_MANS		=	auks.so.8

LIBAUKSAPI		=	../../api/auks/libauksapi.la

slurmplugdir		=	$(libdir)/slurm

slurmplug_LTLIBRARIES	=	auks.la

auks_la_SOURCES		=	slurm-spank-auks.c
auks_la_CPPFLAGS	=	-I$(top_srcdir)/src/api $(SLURM_CPPFLAGS) \
				$(AM_CPPFLAGS) -DBINDIR=\"$(bindir)\"
auks_la_LDFLAGS		=	$(SLURM_LDFLAGS) -module \
				-avoid-version --export-dynamic
auks_la_LIBADD		=	$(LIBAUKSAPI)

if ENABLE_RUST

rust_target_dir		=	$(abs_top_builddir)/rust/target

all-local:
	cd $(top_srcdir)/rust && \
	CARGO_TARGET_DIR=$(rust_target_dir) \
	SLURM_PREFIX=$(SLURM_PREFIX_FOR_RUST) \
	AUKS_BINDIR=$(bindir) \
	AUKS_SYSCONFDIR=$(sysconfdir) \
	$(CARGO) build --release --locked -p auks-spank

install-exec-local:
	$(MKDIR_P) $(DESTDIR)$(slurmplugdir)
	$(INSTALL) -m 755 $(rust_target_dir)/release/libauks_spank.so \
		$(DESTDIR)$(slurmplugdir)/auks_rs.so

uninstall-local:
	rm -f $(DESTDIR)$(slurmplugdir)/auks_rs.so

clean-local:
	cd $(top_srcdir)/rust && \
	CARGO_TARGET_DIR=$(rust_target_dir) $(CARGO) clean

endif

endif

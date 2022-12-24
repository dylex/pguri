MODULES = pguri
EXTENSION = pguri
DATA = pguri--1.0.sql.in
PG_CONFIG = pg_config
PGXS := $(shell pg_config --pgxs)
include $(PGXS)
%.sql: %.sql.in
	sed 's,MODULE_PATHNAME,$$libdir/$*,g' $< >$@

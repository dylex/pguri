MODULES = pguri
EXTENSION = pguri
DATA = pguri--1.0.sql
PG_CONFIG = pg_config
PGXS := $(shell pg_config --pgxs)
include $(PGXS)
# for local testing
pguri.sql: pguri--1.0.sql
	sed 's,MODULE_PATHNAME,$$libdir/$*,g' $< >$@

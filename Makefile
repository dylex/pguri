MODULES = pguri
EXTENSION = pguri
DATA = pguri.sql.in
PG_CONFIG = pg_config
PGXS := $(shell pg_config --pgxs)
include $(PGXS)
%.sql: %.sql.in
	sed 's,MODULE_PATHNAME,$$libdir/$*,g' $< >$@

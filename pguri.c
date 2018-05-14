#include <string.h>
#include <stdlib.h>
#include <postgres.h>
#include <fmgr.h>
#include <funcapi.h>
#include <catalog/pg_type.h>
#include <libpq/pqformat.h>
#include <utils/builtins.h>
#include <utils/array.h>
#include <utils/typcache.h>
#include <server/access/htup_details.h>

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(unsafe_cast);
Datum unsafe_cast(PG_FUNCTION_ARGS);
Datum unsafe_cast(PG_FUNCTION_ARGS)
{
	PG_RETURN_DATUM(PG_GETARG_DATUM(0));
}

#define MIN(A, B) ((B) < (A) ? (B) : (A))

#define STRSEARCH(STR, LEN, P) ({ \
		typeof(LEN) _len = LEN; \
		while (_len-- && !(P)) STR ++; \
		STR; \
	})

static const char *skip_octet(const char *p, const char *e)
{
	if (p >= e)
		return p;
	if (p[0] == '0')
		return &p[1];
	if (p[0] == '1') {
		if (p+1 < e && p[1] >= '0' && p[1] <= '9') {
			if (p+2 < e && p[2] >= '0' && p[2] <= '9')
				return &p[3];
			return &p[2];
		}
		return &p[1];
	}
	if (p[0] == '2') {
		if (p+1 < e) {
			if (p[1] >= '0' && p[1] <= '4') {
				if (p+2 < e && p[2] >= '0' && p[2] <= '9')
					return &p[3];
				return &p[2];
			}
			if (p[1] == '5') {
				if (p+2 < e && p[2] >= '0' && p[2] < '6')
					return &p[3];
				return &p[2];
			}
			if (p[1] >= '6' && p[1] <= '9')
				return &p[2];
		}
		return &p[1];
	}
	if (p[0] >= '3' && p[0] <= '9') {
		if (p+1 < e && p[1] >= '0' && p[1] <= '9')
			return &p[2];
		return &p[1];
	}
	return NULL;
}

static bool isip(const char *p, const char *e)
{
	unsigned i;

	if (p < e-1 && *p == '[')
		return true;

	for (i = 0; i < 4 && p < e; i ++)
	{
		p = skip_octet(p, e);
		if (!p)
			return false;
		if (p >= e)
			return true;
		if (*p != '.')
			return false;
		if (i < 3)
			p ++;
	}

	return p >= e;
}

static void domainname_flip(char *out, const char *in, size_t len)
{
	const char *e = in+len;
	const char *n = in;
	char *o = out+len;

	if (isip(in, e)) {
		memcpy(out, in, len);
		return;
	}

	n = in;
	while (1)
	{
		const char *p = n;
		STRSEARCH(n, e-p, *n == '.');
		o -= n-p;
		memcpy(o, p, n-p);
		if (n >= e)
			break;
		*--o = *n++;
	}
}

static text *domainname_new(const char *str, size_t len)
{
	text *out;
	if (len && str[len-1] == '.')
		len --;
	out = (text *)palloc(VARHDRSZ + len);
	SET_VARSIZE(out, VARHDRSZ + len);
	domainname_flip(VARDATA(out), str, len);
	return out;
}

PG_FUNCTION_INFO_V1(domainname_in);
Datum domainname_in(PG_FUNCTION_ARGS);
Datum domainname_in(PG_FUNCTION_ARGS)
{
	const char *in = PG_GETARG_CSTRING(0);
	size_t len = strlen(in);
	PG_RETURN_TEXT_P(domainname_new(in, len));
}

PG_FUNCTION_INFO_V1(domainname_read);
Datum domainname_read(PG_FUNCTION_ARGS);
Datum domainname_read(PG_FUNCTION_ARGS)
{
	text *in = PG_GETARG_TEXT_PP(0);
	text *out = domainname_new(VARDATA_ANY(in), VARSIZE_ANY_EXHDR(in));
	PG_RETURN_TEXT_P(out);
}

PG_FUNCTION_INFO_V1(domainname_out);
Datum domainname_out(PG_FUNCTION_ARGS);
Datum domainname_out(PG_FUNCTION_ARGS)
{
	text *in = PG_GETARG_TEXT_PP(0);
	size_t len = VARSIZE_ANY_EXHDR(in);
	char *out = palloc(len+1);
	domainname_flip(out, VARDATA_ANY(in), len);
	out[len] = '\0';
	PG_RETURN_CSTRING(out);
}

PG_FUNCTION_INFO_V1(domainname_show);
Datum domainname_show(PG_FUNCTION_ARGS);
Datum domainname_show(PG_FUNCTION_ARGS)
{
	text *in = PG_GETARG_TEXT_PP(0);
	size_t len = VARSIZE_ANY(in);
	text *out = (text *)palloc(len);
	SET_VARSIZE(out, len);
	domainname_flip(VARDATA(out), VARDATA_ANY(in), len - VARHDRSZ);
	PG_RETURN_TEXT_P(out);
}

PG_FUNCTION_INFO_V1(domainname_cat);
Datum domainname_cat(PG_FUNCTION_ARGS);
Datum domainname_cat(PG_FUNCTION_ARGS)
{
	text *left = PG_GETARG_TEXT_PP(0);
	text *right = PG_GETARG_TEXT_PP(1);
	size_t leftlen = VARSIZE_ANY_EXHDR(left);
	size_t rightlen = VARSIZE_ANY_EXHDR(right);
	text *out;
	char *p;
	size_t len = VARHDRSZ+leftlen+rightlen;
	if (leftlen && rightlen)
		len ++;
	out = (text *)palloc(len);
	SET_VARSIZE(out, len);
	p = VARDATA(out);
	memcpy(p, VARDATA_ANY(right), rightlen);
	p += rightlen;
	if (leftlen && rightlen)
		*p++ = '.';
	memcpy(p, VARDATA_ANY(left), leftlen);

	PG_RETURN_TEXT_P(out);
}

#if 0
PG_FUNCTION_INFO_V1(domainname_parents);
Datum domainname_parents(PG_FUNCTION_ARGS);
Datum domainname_parents(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	text *in = PG_GETARG_TEXT_PP(0);
	const char *s = VARDATA_ANY(in);
	const char *p = s, *e = s + VARSIZE_ANY_EXHDR(in);
	unsigned i;

	if (SRF_IS_FIRSTCALL())
		funcctx = SRF_FIRSTCALL_INIT();

	funcctx = SRF_PERCALL_SETUP();

	for (i = 0; i < funcctx->call_cntr && ++p < e; i ++)
		STRSEARCH(p, e-p, *p == '.');

	if (i == funcctx->call_cntr)
		SRF_RETURN_NEXT(funcctx, PointerGetDatum(cstring_to_text_with_len(s, p-s)));
	else
		SRF_RETURN_DONE(funcctx);
}
#else
PG_FUNCTION_INFO_V1(domainname_parents);
Datum domainname_parents(PG_FUNCTION_ARGS);
Datum domainname_parents(PG_FUNCTION_ARGS)
{
	text *in = PG_GETARG_TEXT_PP(0);
	const char *s = VARDATA_ANY(in);
	const char *p = s, *e = s + VARSIZE_ANY_EXHDR(in);
	int nelems = 1;
	int nbytes = ARR_OVERHEAD_NONULLS(1) + VARHDRSZ;
	ArrayType *r;
	char *o;

	while (p < e) 
	{
		STRSEARCH(p, e-p, *p == '.');
		nelems ++;
		nbytes += VARHDRSZ + (p-s);
		nbytes = INTALIGN(nbytes);
		p ++;
	}
	r = (ArrayType *)palloc(nbytes);
	SET_VARSIZE(r, nbytes);
	r->ndim = 1;
	r->dataoffset = 0;
	r->elemtype = get_fn_expr_argtype(fcinfo->flinfo, 0);
	*ARR_DIMS(r) = nelems;
	*ARR_LBOUND(r) = 0;

	p = s;
	o = ARR_DATA_PTR(r);
	SET_VARSIZE(o, VARHDRSZ);
	o = VARDATA(o);
	while (p < e)
	{
		STRSEARCH(p, e-p, *p == '.');
		SET_VARSIZE(o, VARHDRSZ+(p-s));
		o = VARDATA(o);
		memcpy(o, s, p-s);
		o += INTALIGN(p-s);
		p ++;
	}

	PG_RETURN_ARRAYTYPE_P(r);
}
#endif

PG_FUNCTION_INFO_V1(domainname_parts);
Datum domainname_parts(PG_FUNCTION_ARGS);
Datum domainname_parts(PG_FUNCTION_ARGS)
{
	text *in = PG_GETARG_TEXT_PP(0);
	const char *s = VARDATA_ANY(in);
	const char *b = s, *p = s, *e = s + VARSIZE_ANY_EXHDR(in);
	int nelems = 0;
	int nbytes = ARR_OVERHEAD_NONULLS(1);
	ArrayType *r;
	char *o;

	while (p < e) 
	{
		b = p;
		STRSEARCH(p, e-p, *p == '.');
		nelems ++;
		nbytes += VARHDRSZ + (p-b);
		nbytes = INTALIGN(nbytes);
		p ++;
	}
	r = (ArrayType *)palloc(nbytes);
	SET_VARSIZE(r, nbytes);
	r->ndim = 1;
	r->dataoffset = 0;
	r->elemtype = TEXTOID;
	*ARR_DIMS(r) = nelems;
	*ARR_LBOUND(r) = 1;

	p = s;
	o = ARR_DATA_PTR(r);
	while (p < e)
	{
		b = p;
		STRSEARCH(p, e-p, *p == '.');
		SET_VARSIZE(o, VARHDRSZ+(p-b));
		o = VARDATA(o);
		memcpy(o, b, p-b);
		o += INTALIGN(p-b);
		p ++;
	}

	PG_RETURN_ARRAYTYPE_P(r);
}


struct uri_info {
	const char *scheme;
	int scheme_len;
	const char *user;
	int user_len;
	const char *host;
	int host_len;
	int port;
	const char *path;
	int path_len;
	const char *query;
	int query_len;
	const char *fragment;
	int fragment_len;
};

static bool uri_parse(const char *str, size_t len, struct uri_info *uri)
{
	const char *b = str, *p = str, *d, *e = str+len;

	STRSEARCH(p, e-p, *p == ':' || *p == '/' || *p == '@' || *p == '?' || *p == '#');
	if (p+2 < e && p[0] == ':' && p[1] == '/' && p[2] == '/') {
		uri->scheme = b;
		uri->scheme_len = p-b;
		b = p + 3;
	} else {
		uri->scheme = NULL;
		uri->scheme_len = -1;
	}

	d = b;
	STRSEARCH(d, e-d, *d == '/' || *d == '?' || *d == '#');

	p = memchr(b, '@', d-b);
	if (p) {
		uri->user = b;
		uri->user_len = p-b;
		b = p+1;
	} else {
		uri->user = NULL;
		uri->user_len = -1;
	}

	uri->host = b;
	uri->host_len = d-b;
	uri->port = -1;

	p = memrchr(b, ':', d-b);
	if (p++ && d - p <= 5) {
		char portbuf[8], *x = portbuf;
		unsigned long port;
		memcpy(portbuf, p, d-p);
		portbuf[d-p] = 0;

		port = strtoul(portbuf, &x, 10);
		if (!*x && port <= 65536) {
			uri->port = port;
			uri->host_len = p-1-b;
		}
	}

	p = d;
	if (p < e && *p == '/') {
		b = p;
		STRSEARCH(p, e-p, *p == '?' || *p == '#');
		uri->path = b;
		uri->path_len = p-b;
	} else {
		uri->path = NULL;
		uri->path_len = -1;
	}

	if (p < e && *p == '?') {
		b = p += 1;
		STRSEARCH(p, e-p, *p == '#');
		uri->query = b;
		uri->query_len = p-b;
	} else {
		uri->query = NULL;
		uri->query_len = -1;
	}

	if (p < e && *p == '#') {
		p ++;
		uri->fragment = p;
		uri->fragment_len = e-p;
		p = e;
	} else {
		uri->fragment = NULL;
		uri->fragment_len = -1;
	}

	return !*p;
}

enum uri_tuple {
	URI_HOST = 0,
	URI_PORT,
	URI_PATH,
	URI_QUERY,
	URI_USER,
	URI_SCHEME,
	URI_FRAGMENT,

	URI_LEN
};

static HeapTuple uri_new(FunctionCallInfo fcinfo, const char *str, size_t len)
{
	TupleDesc td;
	struct uri_info u;
	Datum d[URI_LEN];
	bool n[URI_LEN];

	if (!uri_parse(str, len, &u))
		ereport(ERROR, (errcode(ERRCODE_INVALID_TEXT_REPRESENTATION),
					errmsg("invalid uri: \"%.*s\"", (int)len, str)));

	if (!(n[URI_SCHEME] = !u.scheme))
		d[URI_SCHEME] = PointerGetDatum(cstring_to_text_with_len(u.scheme, u.scheme_len));
	if (!(n[URI_USER] = !u.user))
		d[URI_USER] = PointerGetDatum(cstring_to_text_with_len(u.user, u.user_len));
	if (!(n[URI_HOST] = !u.host))
		d[URI_HOST] = PointerGetDatum(domainname_new(u.host, u.host_len));
	if (!(n[URI_PORT] = u.port < 0))
		d[URI_PORT] = Int16GetDatum(u.port);
	if (!(n[URI_PATH] = !u.path))
		d[URI_PATH] = PointerGetDatum(cstring_to_text_with_len(u.path, u.path_len));
	if (!(n[URI_QUERY] = !u.query))
		d[URI_QUERY] = PointerGetDatum(cstring_to_text_with_len(u.query, u.query_len));
	if (!(n[URI_FRAGMENT] = !u.fragment))
		d[URI_FRAGMENT] = PointerGetDatum(cstring_to_text_with_len(u.fragment, u.fragment_len));
	get_call_result_type(fcinfo, NULL, &td);
	return heap_form_tuple(BlessTupleDesc(td), d, n);
}

PG_FUNCTION_INFO_V1(uri_in);
Datum uri_in(PG_FUNCTION_ARGS);
Datum uri_in(PG_FUNCTION_ARGS)
{
	const char *str = PG_GETARG_CSTRING(0);
	PG_RETURN_DATUM(HeapTupleGetDatum(uri_new(fcinfo, str, strlen(str))));
}

PG_FUNCTION_INFO_V1(uri_read);
Datum uri_read(PG_FUNCTION_ARGS);
Datum uri_read(PG_FUNCTION_ARGS)
{
	text *in = PG_GETARG_TEXT_PP(0);
	HeapTuple out = uri_new(fcinfo, VARDATA_ANY(in), VARSIZE_ANY_EXHDR(in));
	PG_RETURN_DATUM(HeapTupleGetDatum(out));
}

static void *uri_char(HeapTupleHeader ud, bool hdr, bool term)
{
	TupleDesc td;
	HeapTupleData tuple;
	Datum d[URI_LEN];
	bool n[URI_LEN];
	text *scheme = NULL, *user = NULL, *host = NULL, *path = NULL, *query = NULL, *fragment = NULL;
	int16 port;
	char portbuf[8];
	unsigned schemelen = 0, userlen = 0, hostlen = 0, portlen = 0, pathlen = 0, querylen = 0, fragmentlen = 0;
	unsigned len = hdr ? VARHDRSZ : 0;
	void *out;
	char *p;

	td = lookup_rowtype_tupdesc(HeapTupleHeaderGetTypeId(ud), HeapTupleHeaderGetTypMod(ud));
	tuple.t_len = HeapTupleHeaderGetDatumLength(ud);
	ItemPointerSetInvalid(&(tuple.t_self));
	tuple.t_tableOid = InvalidOid;
	tuple.t_data = ud;
	heap_deform_tuple(&tuple, td, d, n);
	ReleaseTupleDesc(td);

	if (!n[URI_SCHEME])
	{
		scheme = DatumGetTextP(d[URI_SCHEME]);
		len += schemelen = VARSIZE_ANY_EXHDR(scheme);
		len += 3;
	}
	if (!n[URI_USER])
	{
		user = DatumGetTextP(d[URI_USER]);
		len += userlen = VARSIZE_ANY_EXHDR(user);
		len ++;
	}
	if (!n[URI_HOST])
	{
		host = DatumGetTextP(d[URI_HOST]);
		len += hostlen = VARSIZE_ANY_EXHDR(host);
	}
	if (!n[URI_PORT])
	{
		port = DatumGetInt16(d[URI_PORT]);
		len += portlen = snprintf(portbuf, sizeof(portbuf)-1, ":%hu", port);
	}
	if (!n[URI_PATH])
	{
		path = DatumGetTextP(d[URI_PATH]);
		len += pathlen = VARSIZE_ANY_EXHDR(path);
	}
	if (!n[URI_QUERY])
	{
		query = DatumGetTextP(d[URI_QUERY]);
		len += querylen = VARSIZE_ANY_EXHDR(query);
		len ++;
	}
	if (!n[URI_FRAGMENT])
	{
		fragment = DatumGetTextP(d[URI_FRAGMENT]);
		len += fragmentlen = VARSIZE_ANY_EXHDR(fragment);
		len ++;
	}

	len += term;
	out = palloc(len);
	if (hdr) {
		SET_VARSIZE(out, len);
		p = VARDATA(out);
	} else
		p = out;

	if (scheme)
	{
		memcpy(p, VARDATA(scheme), schemelen);
		p += schemelen;
		*p++ = ':';
		*p++ = '/';
		*p++ = '/';
	}
	if (user)
	{
		memcpy(p, VARDATA(user), userlen);
		p += userlen;
		*p++ = '@';
	}
	if (host)
	{
		domainname_flip(p, VARDATA(host), hostlen);
		p += hostlen;
	}
	memcpy(p, portbuf, portlen);
	p += portlen;
	if (path)
	{
		memcpy(p, VARDATA(path), pathlen);
		p += pathlen;
	}
	if (query)
	{
		*p++ = '?';
		memcpy(p, VARDATA(query), querylen);
		p += querylen;
	}
	if (fragment)
	{
		*p++ = '#';
		memcpy(p, VARDATA(fragment), fragmentlen);
		p += fragmentlen;
	}
	if (term)
		*p = '\0';

	return out;
}

PG_FUNCTION_INFO_V1(uri_out);
Datum uri_out(PG_FUNCTION_ARGS);
Datum uri_out(PG_FUNCTION_ARGS)
{
	HeapTupleHeader ud = PG_GETARG_HEAPTUPLEHEADER(0);
	PG_RETURN_CSTRING(uri_char(ud, 0, 1));
}

PG_FUNCTION_INFO_V1(uri_show);
Datum uri_show(PG_FUNCTION_ARGS);
Datum uri_show(PG_FUNCTION_ARGS)
{
	HeapTupleHeader ud = PG_GETARG_HEAPTUPLEHEADER(0);
	PG_RETURN_TEXT_P(uri_char(ud, 1, 0));
}

void _PG_init(void);
void _PG_init()
{
}

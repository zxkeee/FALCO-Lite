#include <stdio.h>
#include "test.h"
#include "fixtures.h"
#include "record.h"

static struct fl_event got[4];
static int ngot;

static void collect(const struct fl_event *e, void *ctx)
{
	(void)ctx;
	if (ngot < 4)
		got[ngot] = *e;
	ngot++;
}

TEST(test_record_roundtrip)
{
	struct fl_event a = ev_exec(4213, 1337, "bash", "/usr/bin/bash");
	struct fl_event b = ev_connect(4213, 1337, "bash", "10.0.0.66", 4444);
	char err[128];
	FILE *f = tmpfile();

	CHECK(f != NULL);
	CHECK(record_write_header(f) == 0);
	CHECK(record_write(f, &a) == 0);
	CHECK(record_write(f, &b) == 0);
	rewind(f);

	ngot = 0;
	CHECK(record_replay(f, collect, NULL, NULL, err, sizeof(err)) == 2);
	fclose(f);
	CHECK(ngot == 2);
	CHECK(!memcmp(&got[0], &a, sizeof(a)));
	CHECK(!memcmp(&got[1], &b, sizeof(b)));
	CHECK(got[1].connect.dport == 4444);
}

TEST(test_record_rejects_garbage)
{
	char err[128] = "";
	FILE *f = tmpfile();

	CHECK(f != NULL);
	fputs("definitely not a record file", f);
	rewind(f);
	CHECK(record_replay(f, collect, NULL, NULL, err, sizeof(err)) == -1);
	fclose(f);
	CHECK(err[0] != '\0');
}

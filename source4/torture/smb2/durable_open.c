/*
   Unix SMB/CIFS implementation.

   test suite for SMB2 durable opens

   Copyright (C) Stefan Metzmacher 2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "torture/torture.h"
#include "torture/smb2/proto.h"

#define CHECK_VAL(v, correct) do { \
	if ((v) != (correct)) { \
		torture_result(tctx, TORTURE_FAIL, "(%s): wrong value for %s got 0x%x - should be 0x%x\n", \
				__location__, #v, (int)v, (int)correct); \
		ret = false; \
	}} while (0)

#define CHECK_STATUS(status, correct) do { \
	if (!NT_STATUS_EQUAL(status, correct)) { \
		torture_result(tctx, TORTURE_FAIL, __location__": Incorrect status %s - should be %s", \
		       nt_errstr(status), nt_errstr(correct)); \
		ret = false; \
		goto done; \
	}} while (0)

#define CHECK_CREATED(__io, __created, __attribute)			\
	do {								\
		CHECK_VAL((__io)->out.create_action, NTCREATEX_ACTION_ ## __created); \
		CHECK_VAL((__io)->out.alloc_size, 0);			\
		CHECK_VAL((__io)->out.size, 0);				\
		CHECK_VAL((__io)->out.file_attr, (__attribute));	\
		CHECK_VAL((__io)->out.reserved2, 0);			\
	} while(0)


/**
 * basic durable_open test.
 * durable state should only be granted when requested
 * along with a batch oplock or a handle lease.
 *
 * This test tests durable open with all possible oplock types.
 */

struct durable_open_vs_oplock {
	const char *level;
	const char *share_mode;
	bool expected;
};

#define NUM_OPLOCK_TYPES 4
#define NUM_SHARE_MODES 8
#define NUM_OPLOCK_OPEN_TESTS ( NUM_OPLOCK_TYPES * NUM_SHARE_MODES )
struct durable_open_vs_oplock durable_open_vs_oplock_table[NUM_OPLOCK_OPEN_TESTS] =
{
	{ "", "", false },
	{ "", "R", false },
	{ "", "W", false },
	{ "", "D", false },
	{ "", "RD", false },
	{ "", "RW", false },
	{ "", "WD", false },
	{ "", "RWD", false },

	{ "s", "", false },
	{ "s", "R", false },
	{ "s", "W", false },
	{ "s", "D", false },
	{ "s", "RD", false },
	{ "s", "RW", false },
	{ "s", "WD", false },
	{ "s", "RWD", false },

	{ "x", "", false },
	{ "x", "R", false },
	{ "x", "W", false },
	{ "x", "D", false },
	{ "x", "RD", false },
	{ "x", "RW", false },
	{ "x", "WD", false },
	{ "x", "RWD", false },

	{ "b", "", true },
	{ "b", "R", true },
	{ "b", "W", true },
	{ "b", "D", true },
	{ "b", "RD", true },
	{ "b", "RW", true },
	{ "b", "WD", true },
	{ "b", "RWD", true },
};

static bool test_one_durable_open_open1(struct torture_context *tctx,
					struct smb2_tree *tree,
					const char *fname,
					struct durable_open_vs_oplock test)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	bool ret = true;
	struct smb2_create io;

	smb2_util_unlink(tree, fname);

	smb2_oplock_create_share(&io, fname,
				 smb2_util_share_access(test.share_mode),
				 smb2_util_oplock_level(test.level));
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, test.expected);
	CHECK_VAL(io.out.oplock_level, smb2_util_oplock_level(test.level));

done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);

	return ret;
}

bool test_durable_open_open1(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	bool ret = true;
	int i;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_open1_%s.dat", generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);

	/* test various oplock levels with durable open */

	for (i = 0; i < NUM_OPLOCK_OPEN_TESTS; i++) {
		ret = test_one_durable_open_open1(tctx,
						  tree,
						  fname,
						  durable_open_vs_oplock_table[i]);
		if (ret == false) {
			goto done;
		}
	}

done:
	smb2_util_unlink(tree, fname);
	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/**
 * basic durable_open test.
 * durable state should only be granted when requested
 * along with a batch oplock or a handle lease.
 *
 * This test tests durable open with all valid lease types.
 */

struct durable_open_vs_lease {
	const char *type;
	const char *share_mode;
	bool expected;
};

#define NUM_LEASE_TYPES 5
#define NUM_LEASE_OPEN_TESTS ( NUM_LEASE_TYPES * NUM_SHARE_MODES )
struct durable_open_vs_lease durable_open_vs_lease_table[NUM_LEASE_OPEN_TESTS] =
{
	{ "", "", false },
	{ "", "R", false },
	{ "", "W", false },
	{ "", "D", false },
	{ "", "RW", false },
	{ "", "RD", false },
	{ "", "WD", false },
	{ "", "RWD", false },

	{ "R", "", false },
	{ "R", "R", false },
	{ "R", "W", false },
	{ "R", "D", false },
	{ "R", "RW", false },
	{ "R", "RD", false },
	{ "R", "DW", false },
	{ "R", "RWD", false },

	{ "RW", "", false },
	{ "RW", "R", false },
	{ "RW", "W", false },
	{ "RW", "D", false },
	{ "RW", "RW", false },
	{ "RW", "RD", false },
	{ "RW", "WD", false },
	{ "RW", "RWD", false },

	{ "RH", "", true },
	{ "RH", "R", true },
	{ "RH", "W", true },
	{ "RH", "D", true },
	{ "RH", "RW", true },
	{ "RH", "RD", true },
	{ "RH", "WD", true },
	{ "RH", "RWD", true },

	{ "RHW", "", true },
	{ "RHW", "R", true },
	{ "RHW", "W", true },
	{ "RHW", "D", true },
	{ "RHW", "RW", true },
	{ "RHW", "RD", true },
	{ "RHW", "WD", true },
	{ "RHW", "RWD", true },
};

static bool test_one_durable_open_open2(struct torture_context *tctx,
					struct smb2_tree *tree,
					const char *fname,
					struct durable_open_vs_lease test)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle _h;
	struct smb2_handle *h = NULL;
	bool ret = true;
	struct smb2_create io;
	struct smb2_lease ls;
	uint64_t lease;

	smb2_util_unlink(tree, fname);

	lease = random();

	smb2_lease_create_share(&io, &ls, false /* dir */, fname,
				smb2_util_share_access(test.share_mode),
				lease,
				smb2_util_lease_state(test.type));
	io.in.durable_open = true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	_h = io.out.file.handle;
	h = &_h;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io.out.durable_open, test.expected);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response.lease_key.data[0], lease);
	CHECK_VAL(io.out.lease_response.lease_key.data[1], ~lease);
	CHECK_VAL(io.out.lease_response.lease_state,
		  smb2_util_lease_state(test.type));
done:
	if (h != NULL) {
		smb2_util_close(tree, *h);
	}
	smb2_util_unlink(tree, fname);
	talloc_free(mem_ctx);

	return ret;
}

bool test_durable_open_open2(struct torture_context *tctx,
			     struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	char fname[256];
	bool ret = true;
	int i;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_open2_%s.dat", generate_random_str(tctx, 8));

	smb2_util_unlink(tree, fname);


	/* test various oplock levels with durable open */

	for (i = 0; i < NUM_LEASE_OPEN_TESTS; i++) {
		ret = test_one_durable_open_open2(tctx,
						  tree,
						  fname,
						  durable_open_vs_lease_table[i]);
		if (ret == false) {
			goto done;
		}
	}

done:
	smb2_util_unlink(tree, fname);
	talloc_free(tree);
	talloc_free(mem_ctx);

	return ret;
}

/*
   basic testing of SMB2 durable opens
   regarding the position information on the handle
*/
bool test_durable_open_file_position(struct torture_context *tctx,
				     struct smb2_tree *tree1,
				     struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_handle h1, h2;
	struct smb2_create io1, io2;
	NTSTATUS status;
	const char *fname = "durable_open_position.dat";
	union smb_fileinfo qfinfo;
	union smb_setfileinfo sfinfo;
	bool ret = true;
	uint64_t pos;

	smb2_util_unlink(tree1, fname);

	smb2_oplock_create(&io1, fname, SMB2_OPLOCK_LEVEL_BATCH);
	io1.in.durable_open = true;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* TODO: check extra blob content */

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree1, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0);
	pos = qfinfo.position_information.out.position;
	torture_comment(tctx, "position: %llu\n",
			(unsigned long long)pos);

	ZERO_STRUCT(sfinfo);
	sfinfo.generic.level = RAW_SFILEINFO_POSITION_INFORMATION;
	sfinfo.generic.in.file.handle = h1;
	sfinfo.position_information.in.position = 0x1000;
	status = smb2_setinfo_file(tree1, &sfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree1, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0x1000);
	pos = qfinfo.position_information.out.position;
	torture_comment(tctx, "position: %llu\n",
			(unsigned long long)pos);

	talloc_free(tree1);
	tree1 = NULL;

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h1;
	status = smb2_getinfo_file(tree2, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_FILE_CLOSED);

	ZERO_STRUCT(io2);
	io2.in.fname = fname;
	io2.in.durable_handle = &h1;

	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(io2.out.durable_open, true);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);
	CHECK_VAL(io2.out.reserved, 0x00);
	CHECK_VAL(io2.out.create_action, NTCREATEX_ACTION_EXISTED);
	CHECK_VAL(io2.out.alloc_size, 0);
	CHECK_VAL(io2.out.size, 0);
	CHECK_VAL(io2.out.file_attr, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.reserved2, 0);

	h2 = io2.out.file.handle;

	ZERO_STRUCT(qfinfo);
	qfinfo.generic.level = RAW_FILEINFO_POSITION_INFORMATION;
	qfinfo.generic.in.file.handle = h2;
	status = smb2_getinfo_file(tree2, mem_ctx, &qfinfo);
	CHECK_STATUS(status, NT_STATUS_OK);
	CHECK_VAL(qfinfo.position_information.out.position, 0x1000);
	pos = qfinfo.position_information.out.position;
	torture_comment(tctx, "position: %llu\n",
			(unsigned long long)pos);

	smb2_util_close(tree2, h2);

	talloc_free(mem_ctx);

	smb2_util_unlink(tree2, fname);
done:
	talloc_free(tree1);
	talloc_free(tree2);

	return ret;
}

/*
  Open, disconnect, oplock break, reconnect.
*/
bool test_durable_open_oplock(struct torture_context *tctx,
			      struct smb2_tree *tree1,
			      struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1, io2;
	struct smb2_handle h1, h2;
	NTSTATUS status;
	char fname[256];
	bool ret = true;

	/* Choose a random name in case the state is left a little funky. */
	snprintf(fname, 256, "durable_open_oplock_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree1, fname);

	/* Create with batch oplock */
	smb2_oplock_create(&io1, fname, SMB2_OPLOCK_LEVEL_BATCH);
	io1.in.durable_open = true;

	io2 = io1;
	io2.in.create_disposition = NTCREATEX_DISP_OPEN;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* Disconnect after getting the batch */
	talloc_free(tree1);
	tree1 = NULL;

	/*
	 * Windows7 (build 7000) will break a batch oplock immediately if the
	 * original client is gone. (ZML: This seems like a bug. It should give
	 * some time for the client to reconnect!)
	 */
	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);
	CHECK_VAL(io2.out.durable_open, true);
	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_BATCH);

	/* What if tree1 tries to come back and reclaim? */
	if (!torture_smb2_connection(tctx, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io1);
	io1.in.fname = fname;
	io1.in.durable_handle = &h1;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

 done:
	smb2_util_close(tree2, h2);
	smb2_util_unlink(tree2, fname);

	talloc_free(tree1);
	talloc_free(tree2);

	return ret;
}

/*
  Open, disconnect, lease break, reconnect.
*/
bool test_durable_open_lease(struct torture_context *tctx,
			     struct smb2_tree *tree1,
			     struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1, io2;
	struct smb2_lease ls1, ls2;
	struct smb2_handle h1, h2;
	NTSTATUS status;
	char fname[256];
	bool ret = true;
	uint64_t lease1, lease2;

	/*
	 * Choose a random name and random lease in case the state is left a
	 * little funky.
	 */
	lease1 = random();
	lease2 = random();
	snprintf(fname, 256, "durable_open_lease_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree1, fname);

	/* Create with lease */
	smb2_lease_create(&io1, &ls1, false /* dir */, fname,
			  lease1, smb2_util_lease_state("RHW"));
	io1.in.durable_open = true;

	smb2_lease_create(&io2, &ls2, false /* dir */, fname,
			  lease2, smb2_util_lease_state("RHW"));
	io2.in.durable_open = true;
	io2.in.create_disposition = NTCREATEX_DISP_OPEN;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io1.out.lease_response.lease_key.data[0], lease1);
	CHECK_VAL(io1.out.lease_response.lease_key.data[1], ~lease1);
	CHECK_VAL(io1.out.lease_response.lease_state,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);

	/* Disconnect after getting the lease */
	talloc_free(tree1);
	tree1 = NULL;

	/*
	 * Windows7 (build 7000) will grant an RH lease immediate (not an RHW?)
	 * even if the original client is gone. (ZML: This seems like a bug. It
	 * should give some time for the client to reconnect! And why RH?)
	 * 
	 * obnox: Current windows 7 and w2k8r2 grant RHW instead of RH.
	 * Test is adapted accordingly.
	 */
	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_VAL(io2.out.durable_open, true);
	CHECK_CREATED(&io2, EXISTED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io2.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io2.out.lease_response.lease_key.data[0], lease2);
	CHECK_VAL(io2.out.lease_response.lease_key.data[1], ~lease2);
	CHECK_VAL(io2.out.lease_response.lease_state,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);

	/* What if tree1 tries to come back and reclaim? */
	if (!torture_smb2_connection(tctx, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io1);
	io1.in.fname = fname;
	io1.in.durable_handle = &h1;
	io1.in.lease_request = &ls1;

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);

 done:
	smb2_util_close(tree2, h2);
	smb2_util_unlink(tree2, fname);

	talloc_free(tree1);
	talloc_free(tree2);

	return ret;
}

/*
  Open, take BRL, disconnect, reconnect.
*/
bool test_durable_open_lock(struct torture_context *tctx,
			    struct smb2_tree *tree)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io;
	struct smb2_lease ls;
	struct smb2_handle h;
	struct smb2_lock lck;
	struct smb2_lock_element el[2];
	NTSTATUS status;
	char fname[256];
	bool ret = true;
	uint64_t lease;

	/*
	 * Choose a random name and random lease in case the state is left a
	 * little funky.
	 */
	lease = random();
	snprintf(fname, 256, "durable_open_lock_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree, fname);

	/* Create with lease */

	smb2_lease_create(&io, &ls, false /* dir */, fname, lease,
			  smb2_util_lease_state("RWH"));
	io.in.durable_open 		= true;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;
	CHECK_CREATED(&io, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io.out.durable_open, true);
	CHECK_VAL(io.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io.out.lease_response.lease_key.data[0], lease);
	CHECK_VAL(io.out.lease_response.lease_key.data[1], ~lease);
	CHECK_VAL(io.out.lease_response.lease_state,
	    SMB2_LEASE_READ|SMB2_LEASE_HANDLE|SMB2_LEASE_WRITE);

	ZERO_STRUCT(lck);
	ZERO_STRUCT(el);
	lck.in.locks		= el;
	lck.in.lock_count	= 0x0001;
	lck.in.lock_sequence	= 0x00000000;
	lck.in.file.handle	= h;
	el[0].offset		= 0;
	el[0].length		= 1;
	el[0].reserved		= 0x00000000;
	el[0].flags		= SMB2_LOCK_FLAG_EXCLUSIVE;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

	/* Disconnect/Reconnect. */
	talloc_free(tree);
	tree = NULL;

	if (!torture_smb2_connection(tctx, &tree)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io);
	io.in.fname = fname;
	io.in.durable_handle = &h;
	io.in.lease_request = &ls;

	status = smb2_create(tree, mem_ctx, &io);
	CHECK_STATUS(status, NT_STATUS_OK);
	h = io.out.file.handle;

	lck.in.file.handle	= h;
	el[0].flags		= SMB2_LOCK_FLAG_UNLOCK;
	status = smb2_lock(tree, &lck);
	CHECK_STATUS(status, NT_STATUS_OK);

 done:
	smb2_util_close(tree, h);
	smb2_util_unlink(tree, fname);
	talloc_free(tree);

	return ret;
}

/*
  Open, disconnect, open in another tree, reconnect.

  This test actually demonstrates a minimum level of respect for the durable
  open in the face of another open. As long as this test shows an inability to
  reconnect after an open, the oplock/lease tests above will certainly
  demonstrate an error on reconnect.
*/
bool test_durable_open_open(struct torture_context *tctx,
			    struct smb2_tree *tree1,
			    struct smb2_tree *tree2)
{
	TALLOC_CTX *mem_ctx = talloc_new(tctx);
	struct smb2_create io1, io2;
	struct smb2_lease ls;
	struct smb2_handle h1, h2;
	NTSTATUS status;
	char fname[256];
	bool ret = true;
	uint64_t lease;

	/*
	 * Choose a random name and random lease in case the state is left a
	 * little funky.
	 */
	lease = random();
	snprintf(fname, 256, "durable_open_lock_%s.dat", generate_random_str(tctx, 8));

	/* Clean slate */
	smb2_util_unlink(tree1, fname);

	/* Create with lease */
	smb2_lease_create_share(&io1, &ls, false /* dir */, fname,
				smb2_util_share_access(""),
				lease,
				smb2_util_lease_state("RH"));
	io1.in.durable_open = true;

	smb2_oplock_create(&io2, fname, SMB2_OPLOCK_LEVEL_NONE);

	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OK);
	h1 = io1.out.file.handle;
	CHECK_VAL(io1.out.durable_open, true);
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	CHECK_VAL(io1.out.oplock_level, SMB2_OPLOCK_LEVEL_LEASE);
	CHECK_VAL(io1.out.lease_response.lease_key.data[0], lease);
	CHECK_VAL(io1.out.lease_response.lease_key.data[1], ~lease);
	CHECK_VAL(io1.out.lease_response.lease_state,
		  smb2_util_lease_state("RH"));

	/* Disconnect */
	talloc_free(tree1);
	tree1 = NULL;

	/* Open the file in tree2 */
	status = smb2_create(tree2, mem_ctx, &io2);
	CHECK_STATUS(status, NT_STATUS_OK);
	h2 = io2.out.file.handle;
	CHECK_CREATED(&io1, CREATED, FILE_ATTRIBUTE_ARCHIVE);

	/* Reconnect */
	if (!torture_smb2_connection(tctx, &tree1)) {
		torture_warning(tctx, "couldn't reconnect, bailing\n");
		ret = false;
		goto done;
	}

	ZERO_STRUCT(io1);
	io1.in.fname = fname;
	io1.in.durable_handle = &h1;
	io1.in.lease_request = &ls;

	/*
	 * Windows7 (build 7000) will give away an open immediately if the
	 * original client is gone. (ZML: This seems like a bug. It should give
	 * some time for the client to reconnect!)
	 */
	status = smb2_create(tree1, mem_ctx, &io1);
	CHECK_STATUS(status, NT_STATUS_OBJECT_NAME_NOT_FOUND);
	h1 = io1.out.file.handle;

 done:
	smb2_util_close(tree2, h2);
	smb2_util_unlink(tree2, fname);
	smb2_util_close(tree1, h1);
	smb2_util_unlink(tree1, fname);

	talloc_free(tree1);
	talloc_free(tree2);

	return ret;
}

struct torture_suite *torture_smb2_durable_open_init(void)
{
	struct torture_suite *suite =
	    torture_suite_create(talloc_autofree_context(), "durable-open");

	torture_suite_add_1smb2_test(suite, "open1", test_durable_open_open1);
	torture_suite_add_1smb2_test(suite, "open2", test_durable_open_open2);
	torture_suite_add_2smb2_test(suite, "file-position",
	    test_durable_open_file_position);
	torture_suite_add_2smb2_test(suite, "oplock", test_durable_open_oplock);
	torture_suite_add_2smb2_test(suite, "lease", test_durable_open_lease);
	torture_suite_add_1smb2_test(suite, "lock", test_durable_open_lock);
	torture_suite_add_2smb2_test(suite, "open", test_durable_open_open);

	suite->description = talloc_strdup(suite, "SMB2-DURABLE-OPEN tests");

	return suite;
}

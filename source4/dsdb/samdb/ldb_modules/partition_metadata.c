/*
   Partitions ldb module - management of metadata.tdb for sequence number

   Copyright (C) Amitay Isaacs <amitay@samba.org> 2011

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

#include "dsdb/samdb/ldb_modules/partition.h"
#include "system/filesys.h"

#define LDB_METADATA_SEQ_NUM	"SEQ_NUM"


/*
 * Read a key with uint64 value
 */
static int partition_metadata_get_uint64(struct ldb_module *module,
					 const char *key, uint64_t *value,
					 uint64_t default_value)
{
	struct partition_private_data *data;
	struct tdb_context *tdb;
	TDB_DATA tdb_key, tdb_data;
	char *value_str;
	TALLOC_CTX *tmp_ctx;

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct partition_private_data);

	if (!data && !data->metadata && !data->metadata->db) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: metadata tdb not initialized");
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return ldb_module_oom(module);
	}

	tdb = data->metadata->db->tdb;

	tdb_key.dptr = (uint8_t *)discard_const_p(char, key);
	tdb_key.dsize = strlen(key);

	tdb_data = tdb_fetch(tdb, tdb_key);
	if (!tdb_data.dptr) {
		if (tdb_error(tdb) == TDB_ERR_NOEXIST) {
			*value = default_value;
			return LDB_SUCCESS;
		} else {
			return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
						tdb_errorstr(tdb));
		}
	}

	value_str = talloc_strndup(tmp_ctx, (char *)tdb_data.dptr, tdb_data.dsize);
	if (value_str == NULL) {
		SAFE_FREE(tdb_data.dptr);
		talloc_free(tmp_ctx);
		return ldb_module_oom(module);
	}

	*value = strtoull(value_str, NULL, 10);

	SAFE_FREE(tdb_data.dptr);
	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}


/*
 * Write a key with uin64 value
 */
static int partition_metadata_set_uint64(struct ldb_module *module,
					 const char *key, uint64_t value,
					 bool insert)
{
	struct partition_private_data *data;
	struct tdb_context *tdb;
	TDB_DATA tdb_key, tdb_data;
	int tdb_flag;
	char *value_str;
	TALLOC_CTX *tmp_ctx;

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct partition_private_data);

	if (!data && !data->metadata && !data->metadata->db) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: metadata tdb not initialized");
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return ldb_module_oom(module);
	}

	tdb = data->metadata->db->tdb;

	value_str = talloc_asprintf(tmp_ctx, "%llu", (unsigned long long)value);
	if (value_str == NULL) {
		talloc_free(tmp_ctx);
		return ldb_module_oom(module);
	}

	tdb_key.dptr = (uint8_t *)discard_const_p(char, key);
	tdb_key.dsize = strlen(key);

	tdb_data.dptr = (uint8_t *)value_str;
	tdb_data.dsize = strlen(value_str);

	if (insert) {
		tdb_flag = TDB_INSERT;
	} else {
		tdb_flag = TDB_MODIFY;
	}

	if (tdb_store(tdb, tdb_key, tdb_data, tdb_flag) != 0) {
		talloc_free(tmp_ctx);
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					tdb_errorstr(tdb));
	}

	talloc_free(tmp_ctx);

	return LDB_SUCCESS;
}


/*
 * Open sam.ldb.d/metadata.tdb.
 */
static int partition_metadata_open(struct ldb_module *module, bool create)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	TALLOC_CTX *tmp_ctx;
	struct partition_private_data *data;
	struct loadparm_context *lp_ctx;
	const char *sam_name;
	char *filename, *dirname;
	int open_flags;

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct partition_private_data);
	if (!data || !data->metadata) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: metadata not initialized");
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return ldb_module_oom(module);
	}

	sam_name = (const char *)ldb_get_opaque(ldb, "ldb_url");
	if (strncmp("tdb://", sam_name, 6) == 0) {
		sam_name += 6;
	}
	if (!sam_name) {
		talloc_free(tmp_ctx);
		return ldb_operr(ldb);
	}
	filename = talloc_asprintf(tmp_ctx, "%s.d/metadata.tdb", sam_name);
	if (!filename) {
		talloc_free(tmp_ctx);
		return ldb_oom(ldb);
	}

	open_flags = O_RDWR;
	if (create) {
		open_flags |= O_CREAT;

		/* While provisioning, sam.ldb.d directory may not exist,
		 * so create it. Ignore errors, if it already exists. */
		dirname = talloc_asprintf(tmp_ctx, "%s.d", sam_name);
		if (!dirname) {
			talloc_free(tmp_ctx);
			return ldb_oom(ldb);
		}

		mkdir(dirname, 0700);
		talloc_free(dirname);
	}

	lp_ctx = talloc_get_type_abort(ldb_get_opaque(ldb, "loadparm"),
				       struct loadparm_context);

	data->metadata->db = tdb_wrap_open(data->metadata, filename, 10,
					      TDB_DEFAULT, open_flags, 0660,
					      lp_ctx);
	if (data->metadata->db == NULL) {
		talloc_free(tmp_ctx);
		if (create) {
			ldb_debug(ldb, LDB_DEBUG_ERROR,
				  "partition_metadata: Unable to create %s",
				  filename);
		}
		return LDB_ERR_OPERATIONS_ERROR;
	}

	talloc_free(tmp_ctx);
	return LDB_SUCCESS;
}


/*
 * Set the sequence number calculated from older logic (sum of primary sequence
 * numbers for each partition) as LDB_METADATA_SEQ_NUM key.
 */
static int partition_metadata_set_sequence_number(struct ldb_module *module)
{
	struct partition_private_data *data;
	struct ldb_result *res;
	struct ldb_request *req;
	struct ldb_seqnum_request *seq;
	struct ldb_seqnum_result *seqr;
	struct ldb_extended *ext;
	TALLOC_CTX *tmp_ctx;
	int ret;
	uint64_t seq_number;

	data = talloc_get_type_abort(ldb_module_get_private(module),
				    struct partition_private_data);
	if (!data || !data->metadata) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: metadata not initialized");
	}

	tmp_ctx = talloc_new(data->metadata);
	if (tmp_ctx == NULL) {
		return ldb_module_oom(module);
	}

	res = talloc_zero(tmp_ctx, struct ldb_result);
	if (res == NULL) {
		talloc_free(tmp_ctx);
		return ldb_module_oom(module);
	}

	seq = talloc_zero(tmp_ctx, struct ldb_seqnum_request);
	if (seq == NULL) {
		talloc_free(tmp_ctx);
		return ldb_module_oom(module);
	}
	seq->type = LDB_SEQ_HIGHEST_SEQ;

	/* Build an extended request, so it can be passed to each partition in
	   partition_sequence_number_from_partitions() */
	ret = ldb_build_extended_req(&req,
				     ldb_module_get_ctx(module),
				     tmp_ctx,
				     LDB_EXTENDED_SEQUENCE_NUMBER,
				     seq,
				     NULL,
				     res,
				     ldb_extended_default_callback,
				     NULL);
	LDB_REQ_SET_LOCATION(req);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	ret = partition_sequence_number_from_partitions(module, req, &ext);
	if (ret != LDB_SUCCESS) {
		talloc_free(tmp_ctx);
		return ret;
	}

	seqr = talloc_get_type_abort(ext->data, struct ldb_seqnum_result);
	seq_number = seqr->seq_num;

	talloc_free(tmp_ctx);

	return partition_metadata_set_uint64(module, LDB_METADATA_SEQ_NUM, seq_number, true);
}


/*
 * Initialize metadata. Load metadata.tdb.
 * If missing, create it and fill in sequence number
 */
int partition_metadata_init(struct ldb_module *module)
{
	struct partition_private_data *data;
	int ret;

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct partition_private_data);

	data->metadata = talloc_zero(data, struct partition_metadata);
	if (data->metadata == NULL) {
		return ldb_module_oom(module);
	}

	ret = partition_metadata_open(module, false);
	if (ret == LDB_SUCCESS) {
		goto end;
	}

	/* metadata.tdb does not exist, create it */
	DEBUG(2, ("partition_metadata: Migrating partition metadata\n"));
	ret = partition_metadata_open(module, true);
	if (ret != LDB_SUCCESS) {
		talloc_free(data->metadata);
		data->metadata = NULL;
		goto end;
	}

	ret = partition_metadata_set_sequence_number(module);
	if (ret != LDB_SUCCESS) {
		talloc_free(data->metadata);
		data->metadata = NULL;
	}

end:
	return ret;
}


/*
 * Read the sequence number, default to 0 if LDB_METADATA_SEQ_NUM key is missing
 */
int partition_metadata_sequence_number(struct ldb_module *module, uint64_t *value)
{
	return partition_metadata_get_uint64(module,
					     LDB_METADATA_SEQ_NUM,
					     value,
					     0);
}


/*
 * Increment the sequence number, returning the new sequence number
 */
int partition_metadata_sequence_number_increment(struct ldb_module *module, uint64_t *value)
{
	struct partition_private_data *data;
	int ret;

	data = talloc_get_type_abort(ldb_module_get_private(module),
				    struct partition_private_data);
	if (!data && !data->metadata) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: metadata not initialized");
	}

	if (data->metadata->in_transaction == 0) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: increment sequence number without transaction");
	}

	ret = partition_metadata_get_uint64(module, LDB_METADATA_SEQ_NUM, value, 0);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	(*value)++;
	ret = partition_metadata_set_uint64(module, LDB_METADATA_SEQ_NUM, *value, false);
	return ret;
}


/*
 * Transaction start
 */
int partition_metadata_start_trans(struct ldb_module *module)
{
	struct partition_private_data *data;
	struct tdb_context *tdb;

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct partition_private_data);
	if (!data && !data->metadata && !data->metadata->db) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: metadata not initialized");
	}
	tdb = data->metadata->db->tdb;

	if (tdb_transaction_start(tdb) != 0) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					tdb_errorstr(tdb));
	}

	data->metadata->in_transaction++;

	return LDB_SUCCESS;
}


/*
 * Transaction prepare commit
 */
int partition_metadata_prepare_commit(struct ldb_module *module)
{
	struct partition_private_data *data;
	struct tdb_context *tdb;

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct partition_private_data);
	if (!data && !data->metadata && !data->metadata->db) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: metadata not initialized");
	}
	tdb = data->metadata->db->tdb;

	if (data->metadata->in_transaction == 0) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: not in transaction");
	}

	if (tdb_transaction_prepare_commit(tdb) != 0) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					tdb_errorstr(tdb));
	}

	return LDB_SUCCESS;
}


/*
 * Transaction end
 */
int partition_metadata_end_trans(struct ldb_module *module)
{
	struct partition_private_data *data;
	struct tdb_context *tdb;

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct partition_private_data);
	if (!data && !data->metadata && !data->metadata->db) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: metadata not initialized");
	}
	tdb = data->metadata->db->tdb;

	if (data->metadata->in_transaction == 0) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: not in transaction");
	}

	data->metadata->in_transaction--;

	if (tdb_transaction_commit(tdb) != 0) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					tdb_errorstr(tdb));
	}

	return LDB_SUCCESS;
}


/*
 * Transaction delete
 */
int partition_metadata_del_trans(struct ldb_module *module)
{
	struct partition_private_data *data;
	struct tdb_context *tdb;

	data = talloc_get_type_abort(ldb_module_get_private(module),
				     struct partition_private_data);
	if (!data && !data->metadata && !data->metadata->db) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: metadata not initialized");
	}
	tdb = data->metadata->db->tdb;

	if (data->metadata->in_transaction == 0) {
		return ldb_module_error(module, LDB_ERR_OPERATIONS_ERROR,
					"partition_metadata: not in transaction");
	}

	data->metadata->in_transaction--;

	tdb_transaction_cancel(tdb);

	return LDB_SUCCESS;
}

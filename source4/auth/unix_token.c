/*
   Unix SMB/CIFS implementation.

   Deal with unix elements in the security token

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett 2011

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
#include "auth/auth.h"
#include "libcli/wbclient/wbclient.h"
#include "param/param.h"

/*
  form a security_unix_token from the current security_token
*/
NTSTATUS security_token_to_unix_token(TALLOC_CTX *mem_ctx,
				      struct wbc_context *wbc_ctx,
				      struct security_token *token,
				      struct security_unix_token **sec)
{
	uint32_t s, g;
	NTSTATUS status;
	struct id_map *ids;
	struct composite_context *ctx;

	/* we can't do unix security without a user and group */
	if (token->num_sids < 2) {
		return NT_STATUS_ACCESS_DENIED;
	}

	*sec = talloc_zero(mem_ctx, struct security_unix_token);
	if (*sec == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ids = talloc_zero_array(mem_ctx, struct id_map, token->num_sids);
	NT_STATUS_HAVE_NO_MEMORY(ids);

	for (s=0; s < token->num_sids; s++) {
		ids[s].sid = &token->sids[s];
		ids[s].status = ID_UNKNOWN;
	}

	ctx = wbc_sids_to_xids_send(wbc_ctx, ids, token->num_sids, ids);
	NT_STATUS_HAVE_NO_MEMORY(ctx);

	status = wbc_sids_to_xids_recv(ctx, &ids);
	NT_STATUS_NOT_OK_RETURN(status);

	g = token->num_sids;
	if (ids[0].xid.type != ID_TYPE_BOTH) {
		g--;
	}
	(*sec)->ngroups = g;
	(*sec)->groups = talloc_array(*sec, gid_t, (*sec)->ngroups);
	NT_STATUS_HAVE_NO_MEMORY((*sec)->groups);

	g=0;
	if (ids[0].xid.type == ID_TYPE_BOTH) {
		(*sec)->uid = ids[0].xid.id;
		(*sec)->groups[g] = ids[0].xid.id;
		g++;
	} else if (ids[0].xid.type == ID_TYPE_UID) {
		(*sec)->uid = ids[0].xid.id;
	} else {
		return NT_STATUS_INVALID_SID;
	}

	if (ids[1].xid.type == ID_TYPE_BOTH ||
	    ids[1].xid.type == ID_TYPE_GID) {
		(*sec)->gid = ids[1].xid.id;
		(*sec)->groups[g] = ids[1].xid.id;
		g++;
	} else {
		return NT_STATUS_INVALID_SID;
	}

	for (s=2; s < token->num_sids; s++) {
		if (ids[s].xid.type == ID_TYPE_BOTH ||
		    ids[s].xid.type == ID_TYPE_GID) {
			(*sec)->groups[g] = ids[s].xid.id;
			g++;
		} else {
			return NT_STATUS_INVALID_SID;
		}
	}

	TALLOC_FREE(ids);

	return NT_STATUS_OK;
}

/*
  Fill in the auth_user_info_unix and auth_unix_token elements in a struct session_info
*/
NTSTATUS auth_session_info_fill_unix( struct wbc_context *wbc_ctx,
				     struct loadparm_context *lp_ctx,
				     struct auth_session_info *session_info)
{
	char *su;
	size_t len;
	NTSTATUS status = security_token_to_unix_token(session_info, wbc_ctx,
						       session_info->security_token,
						       &session_info->unix_token);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	session_info->unix_info = talloc_zero(session_info, struct auth_user_info_unix);
	NT_STATUS_HAVE_NO_MEMORY(session_info->unix_info);

	session_info->unix_info->system = security_token_is_system(session_info->security_token);

	session_info->unix_info->unix_name = talloc_asprintf(session_info->unix_info,
							     "%s%s%s", session_info->info->domain_name,
							     lpcfg_winbind_separator(lp_ctx),
							     session_info->info->account_name);
	NT_STATUS_HAVE_NO_MEMORY(session_info->unix_info->unix_name);

	len = strlen(session_info->info->account_name) + 1;
	session_info->unix_info->sanitized_username = su = talloc_array(session_info->unix_info, char, len);
	NT_STATUS_HAVE_NO_MEMORY(su);

	alpha_strcpy(su, session_info->info->account_name,
		     ". _-$", len);

	return NT_STATUS_OK;
}
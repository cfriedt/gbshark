/* packet-greybus-common.c
 *
 * Definitions for Greybus packet disassembly structures and routines
 * By Christopher Friedt <chrisfriedt@gmail.com>
 * Copyright 2020 Friedt Professional Engineering Services, Inc
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Specification: https://github.com/projectara/greybus-spec
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "config.h"

#include <epan/decode_as.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>

#include "greybus/greybus_types.h"
#include "greybus/greybus_manifest.h"
#include "greybus/greybus_protocols.h"

#include "packet-greybus-common.h"

const true_false_string true_false = { "True", "False" };

static int hf_greybus_size = -1;
static int hf_greybus_id = -1;
static int hf_greybus_resp = -1;
static int hf_greybus_status = -1;
int hf_greybus_pad = -1;

static int hf_greybus_cport_shutdown_phase = -1;

hf_register_info greybus_common_hf[] = {
	{
		&hf_greybus_size,
		{
			"Message Size",
			"greybus.op.size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_id,
		{
			"Message ID",
			"greybus.op.id",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_resp,
		{
			"Response",
			"greybus.op.response",
			FT_BOOLEAN, 8,
			TFS(&true_false), 0x80,
			NULL, HFILL,
		},
	},
	/* protocols have overlapping types, so "greybus.op.type" must be registered separately by each protocol */
	{
		&hf_greybus_status,
		{
			"Message Status",
			"greybus.op.status",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_pad,
		{
			"Padding",
			"greybus.op.pad",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL,
		},
	},

	{
		&hf_greybus_cport_shutdown_phase,
		{
			"Phase",
			"greybus.cport_shutdown.phase",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
};
const size_t greybus_common_hf_size = array_length(greybus_common_hf);

guint greybus_dissect_header(tvbuff_t *tvb, packet_info *pinfo, int proto, int ett, proto_tree *tree, proto_tree **subtree,
	struct gb_operation_msg_hdr *header, const char *protocol_name, const value_string *packettypenames, int hf_greybus_type)
{
    proto_item *ti = NULL;
    gint offset = 0;

    /* TODO: Allocate frame data with hints for upper layers */

    if (!tvb_bytes_exist(tvb, offset, sizeof(*header))) {
        // indicate somehow that there is a malformed packet?
        return 0;
    }

    ti = proto_tree_add_protocol_format(tree, proto, tvb, 0, tvb_captured_length(tvb), "Greybus Operation");
    *subtree = proto_item_add_subtree(ti, ett);

    /* Common header */
    header->size = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(*subtree, hf_greybus_size, tvb, offset, 2, header->size);
    offset += 2;
    header->operation_id = tvb_get_letohs(tvb, offset);
    proto_tree_add_uint(*subtree, hf_greybus_id, tvb, offset, 2, header->operation_id);
    offset += 2;
    header->type = tvb_get_guint8(tvb, offset);
    proto_tree_add_boolean(*subtree, hf_greybus_resp, tvb, offset, 1, header->type);
    offset += 0;
    proto_tree_add_uint(*subtree, hf_greybus_type, tvb, offset, 1, header->type);
    offset += 1;
    header->result = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(*subtree, hf_greybus_status, tvb, offset, 1, header->result);
    offset += 1;
    tvb_memcpy(tvb, header->pad, offset, sizeof(header->pad));
    proto_tree_add_bytes(*subtree, hf_greybus_pad, tvb, offset, sizeof(header->pad), header->pad);
    offset += sizeof(header->pad);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, protocol_name);
    proto_item_append_text(*subtree, ", Type %s", val_to_str(header->type & ~0x80, packettypenames, "Unknown (0x%02x)"));
    col_clear(pinfo->cinfo, COL_INFO);

    if (!tvb_bytes_exist(tvb, offset, header->size - sizeof(*header))) {
        // indicate somehow that there is a malformed packet?
        return 0;
    }

    return offset;
}

void greybus_dissect_cport_shutdown(tvbuff_t *tvb, packet_info *pinfo, int ett, proto_tree *tree, struct gb_operation_msg_hdr *header)
{
    (void) pinfo;
    struct gb_cport_shutdown_request request;
    guint offset = sizeof(*header);
    proto_tree  *payload_tree;

    if (tvb_bytes_exist(tvb, offset, sizeof(request))) {
        request.phase = tvb_get_guint8(tvb, offset);
        payload_tree = proto_tree_add_subtree_format(tree, tvb, offset, sizeof(request), ett, NULL,
            "Phase %u", request.phase);
        proto_tree_add_uint(payload_tree, hf_greybus_cport_shutdown_phase, tvb, offset, 1, request.phase);
        offset += sizeof(request);
    } else {
        // indicate somehow that there is a malformed packet?
    }
}

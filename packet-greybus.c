/* packet-greybus.h
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

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>
#include "packet-greybus.h"

#include <stdint.h>
#include "greybus_types.h"
#include "greybus_protocols.h"

#define GREYBUS_PROTOCOL_NAME "Greybus Protocol"
#define GREYBUS_PROTOCOL_SHORT_NAME "Greybus"
#define GREYBUS_PROTOCOL_FILTER_NAME "greybus"

void proto_register_greybus(void);
void proto_reg_handoff_greybus(void);

static int proto_greybus = -1;

static int hf_greybus_size;
static int hf_greybus_id;
static int hf_greybus_resp;
static int hf_greybus_type;
static int hf_greybus_status;
static int hf_greybus_pad;

static gint ett_greybus = -1;
static dissector_handle_t greybus_handle;
static const true_false_string true_false = { "True", "False" };

#define _decl(x) { GB_CONTROL_TYPE_ ## x, #x }
static const value_string packettypenames[] = {
	_decl(VERSION),
	_decl(PROBE_AP),
	_decl(GET_MANIFEST_SIZE),
	_decl(GET_MANIFEST),
	_decl(CONNECTED),
	_decl(DISCONNECTED),
	_decl(TIMESYNC_ENABLE),
	_decl(TIMESYNC_DISABLE),
	_decl(TIMESYNC_AUTHORITATIVE),
	_decl(BUNDLE_VERSION),
	_decl(DISCONNECTING),
	_decl(TIMESYNC_GET_LAST_EVENT),
	_decl(MODE_SWITCH),
	_decl(BUNDLE_SUSPEND),
	_decl(BUNDLE_RESUME),
	_decl(BUNDLE_DEACTIVATE),
	_decl(BUNDLE_ACTIVATE),
	_decl(INTF_SUSPEND_PREPARE),
	_decl(INTF_DEACTIVATE_PREPARE),
	_decl(INTF_HIBERNATE_ABORT),
	{ 0, NULL },
};

static hf_register_info greybus_hf[] = {
	{
		&hf_greybus_size,
		{
			GREYBUS_PROTOCOL_SHORT_NAME " Message Size",
			GREYBUS_PROTOCOL_FILTER_NAME ".size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_id,
		{
			GREYBUS_PROTOCOL_SHORT_NAME " Message ID",
			GREYBUS_PROTOCOL_FILTER_NAME ".id",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_resp,
		{
			GREYBUS_PROTOCOL_SHORT_NAME " Response",
			GREYBUS_PROTOCOL_FILTER_NAME ".response",
			FT_BOOLEAN, 8,
			TFS(&true_false), 0x80,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_type,
		{
			GREYBUS_PROTOCOL_SHORT_NAME " Message Type",
			GREYBUS_PROTOCOL_FILTER_NAME ".type",
			FT_UINT8, BASE_DEC,
			VALS(packettypenames), ~0x80,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_status,
		{
			GREYBUS_PROTOCOL_SHORT_NAME " Message Status",
			GREYBUS_PROTOCOL_FILTER_NAME ".status",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_pad,
		{
			GREYBUS_PROTOCOL_SHORT_NAME " (padding)",
			GREYBUS_PROTOCOL_FILTER_NAME ".pad",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
};
static gint *greybus_ett[] = {
    &ett_greybus
};

static int
dissect_greybus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    gint offset = 0;
    guint8 packet_type = ~0x80 & tvb_get_guint8(tvb, 4);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, GREYBUS_PROTOCOL_SHORT_NAME);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_greybus, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Type %s", val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));
    proto_tree *greybus_tree = proto_item_add_subtree(ti, ett_greybus);
    proto_tree_add_item(greybus_tree, hf_greybus_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(greybus_tree, hf_greybus_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(greybus_tree, hf_greybus_resp, tvb, offset, 1, ENC_NA);
    offset += 0;
    proto_tree_add_item(greybus_tree, hf_greybus_type, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(greybus_tree, hf_greybus_status, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(greybus_tree, hf_greybus_pad, tvb, offset, 2, ENC_NA);
    offset += 2;

    return tvb_captured_length(tvb);
}

void proto_register_greybus(void)
{
    proto_greybus = proto_register_protocol(
        GREYBUS_PROTOCOL_NAME,
        GREYBUS_PROTOCOL_SHORT_NAME,
        GREYBUS_PROTOCOL_FILTER_NAME
        );

    proto_register_field_array(proto_greybus, greybus_hf, array_length(greybus_hf));
    proto_register_subtree_array(greybus_ett, array_length(greybus_ett));
}

void proto_reg_handoff_greybus(void)
{
    greybus_handle = create_dissector_handle(dissect_greybus, proto_greybus);
    dissector_add_uint("tcp.port", GREYBUS_PORT, greybus_handle);
}

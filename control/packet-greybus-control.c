/* packet-greybus-control.c
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

#include "config.h"
#include "packet-greybus-control.h"

#define GREYBUS_PROTOCOL_SHORT_NAME "Greybus Control"
#define GREYBUS_PROTOCOL_NAME GREYBUS_PROTOCOL_SHORT_NAME " Protocol"
#define GREYBUS_PROTOCOL_FILTER_NAME "greybus.control"

void proto_register_greybus(void);
void proto_reg_handoff_greybus(void);

static gpointer greybus_value(packet_info *pinfo);
static void greybus_prompt(packet_info *pinfo, gchar* result);

static int proto_greybus = -1;

static int hf_greybus_size = -1;
static int hf_greybus_id = -1;
static int hf_greybus_resp = -1;
static int hf_greybus_type = -1;
static int hf_greybus_status = -1;
static int hf_greybus_pad = -1;
static int hf_greybus_version_major = -1;
static int hf_greybus_version_minor = -1;
static int hf_greybus_manifest_size = -1;
static int hf_greybus_manifest = -1;
static int hf_greybus_bundle_id = -1;
static int hf_greybus_result = -1;
static int hf_greybus_cport_id = -1;

static gint ett_greybus = -1;
static dissector_handle_t greybus_handle;
static const true_false_string true_false = { "True", "False" };
static dissector_table_t greybus_dissector_table;

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
			"Message Size",
			GREYBUS_PROTOCOL_FILTER_NAME ".size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_id,
		{
			"Message ID",
			GREYBUS_PROTOCOL_FILTER_NAME ".id",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_resp,
		{
			"Response",
			GREYBUS_PROTOCOL_FILTER_NAME ".response",
			FT_BOOLEAN, 8,
			TFS(&true_false), 0x80,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_type,
		{
			"Message Type",
			GREYBUS_PROTOCOL_FILTER_NAME ".type",
			FT_UINT8, BASE_DEC,
			VALS(packettypenames), ~0x80,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_status,
		{
			"Message Status",
			GREYBUS_PROTOCOL_FILTER_NAME ".status",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_pad,
		{
			"(padding)",
			GREYBUS_PROTOCOL_FILTER_NAME ".pad",
			FT_NONE, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_version_major,
		{
			"Major Version",
			GREYBUS_PROTOCOL_FILTER_NAME ".version.major",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_version_minor,
		{
			"Minor Version",
			GREYBUS_PROTOCOL_FILTER_NAME ".version.minor",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_manifest_size,
		{
			"Manifest Size",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_manifest,
		{
			"Manifest",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_bundle_id,
		{
			"Bundle Id",
			GREYBUS_PROTOCOL_FILTER_NAME ".bundle.id",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_result,
		{
			"Result",
			GREYBUS_PROTOCOL_FILTER_NAME ".result",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_cport_id,
		{
			"CPort ID",
			GREYBUS_PROTOCOL_FILTER_NAME ".cport.id",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
};
static gint *greybus_ett[] = {
    &ett_greybus
};
static build_valid_func greybus_da_build_value[1] = {
		greybus_value,
};
static decode_as_value_t greybus_da_values = {
		greybus_prompt,
		1,
		greybus_da_build_value,
};
static decode_as_t greybus_da = {
		GREYBUS_PROTOCOL_SHORT_NAME,
		GREYBUS_PROTOCOL_FILTER_NAME ".type",
#if VERSION_MAJOR == 2
		"",
#endif
		1,
		0,
		&greybus_da_values,
		NULL,
		NULL,
		decode_as_default_populate_list,
		decode_as_default_reset,
		decode_as_default_change,
		NULL,
};

static int
dissect_greybus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    gint offset = 0;
    guint8 packet_type = ~0x80 & tvb_get_guint8(tvb, 4);
    bool response = !!(0x80 & tvb_get_guint8(tvb, 4));
    col_set_str(pinfo->cinfo, COL_PROTOCOL, GREYBUS_PROTOCOL_SHORT_NAME);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_greybus, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", Type %s", val_to_str(packet_type, packettypenames, "Unknown (0x%02x)"));
    proto_tree *greybus_tree = proto_item_add_subtree(ti, ett_greybus);

    /* Common header */
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

    switch(packet_type) {
    case GB_CONTROL_TYPE_VERSION:
        proto_tree_add_item(greybus_tree, hf_greybus_version_major, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(greybus_tree, hf_greybus_version_minor, tvb, offset, 1, ENC_NA);
        offset += 1;
		break;
	case GB_CONTROL_TYPE_GET_MANIFEST_SIZE:
		if (response) {
	        proto_tree_add_item(greybus_tree, hf_greybus_manifest_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	        offset += 2;
		}
		break;
	case GB_CONTROL_TYPE_GET_MANIFEST:
		if (response) {
			/* TODO: convert to a custom string buffer */
			size_t remaining = tvb_captured_length(tvb) - offset;
	        proto_tree_add_item(greybus_tree, hf_greybus_manifest, tvb, offset, remaining, ENC_NA);
	        offset += remaining;
		}
		break;
	case GB_CONTROL_TYPE_CONNECTED:
		if (!response) {
	        proto_tree_add_item(greybus_tree, hf_greybus_cport_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	        offset += 2;
		}
		break;
	case GB_CONTROL_TYPE_DISCONNECTED:
		if (!response) {
	        proto_tree_add_item(greybus_tree, hf_greybus_cport_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	        offset += 2;
		}
		break;
	case GB_CONTROL_TYPE_BUNDLE_VERSION:
		break;
	case GB_CONTROL_TYPE_DISCONNECTING:
		if (!response) {
	        proto_tree_add_item(greybus_tree, hf_greybus_cport_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	        offset += 2;
		}
		break;
	case GB_CONTROL_TYPE_MODE_SWITCH:
		break;
	case GB_CONTROL_TYPE_BUNDLE_SUSPEND:
		if (response) {
	        proto_tree_add_item(greybus_tree, hf_greybus_result, tvb, offset, 1, ENC_NA);
	        offset += 1;
		} else {
	        proto_tree_add_item(greybus_tree, hf_greybus_bundle_id, tvb, offset, 1, ENC_NA);
	        offset += 1;
		}
		break;
	case GB_CONTROL_TYPE_BUNDLE_RESUME:
		if (response) {
			/* TODO: Bundle PM status */
	        proto_tree_add_item(greybus_tree, hf_greybus_result, tvb, offset, 1, ENC_NA);
	        offset += 1;
		} else {
	        proto_tree_add_item(greybus_tree, hf_greybus_bundle_id, tvb, offset, 1, ENC_NA);
	        offset += 1;
		}
		break;
	case GB_CONTROL_TYPE_BUNDLE_DEACTIVATE:
		break;
	case GB_CONTROL_TYPE_BUNDLE_ACTIVATE:
		if (response) {
	        proto_tree_add_item(greybus_tree, hf_greybus_result, tvb, offset, 1, ENC_NA);
	        offset += 1;
		} else {
	        proto_tree_add_item(greybus_tree, hf_greybus_bundle_id, tvb, offset, 1, ENC_NA);
	        offset += 1;
		}
		break;
	case GB_CONTROL_TYPE_INTF_SUSPEND_PREPARE:
		break;
	case GB_CONTROL_TYPE_INTF_DEACTIVATE_PREPARE:
		break;
	case GB_CONTROL_TYPE_INTF_HIBERNATE_ABORT:
		break;

	case GB_CONTROL_TYPE_TIMESYNC_GET_LAST_EVENT: /* Not used in practise */
	case GB_CONTROL_TYPE_TIMESYNC_ENABLE:
	case GB_CONTROL_TYPE_TIMESYNC_DISABLE:
	case GB_CONTROL_TYPE_TIMESYNC_AUTHORITATIVE:
	case GB_CONTROL_TYPE_PROBE_AP: /* Not in the spec */
	default:
		break;
    }

    return tvb_captured_length(tvb);
}

static gpointer greybus_value(packet_info *pinfo)
{
       return p_get_proto_data(pinfo->pool, pinfo, proto_greybus, 0);
}

static void greybus_prompt(packet_info *pinfo, gchar* result)
{
       (void)pinfo;
       g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, GREYBUS_PROTOCOL_SHORT_NAME);
}

void proto_register_greybus(void)
{
    proto_greybus = proto_register_protocol(GREYBUS_PROTOCOL_NAME, GREYBUS_PROTOCOL_SHORT_NAME, GREYBUS_PROTOCOL_FILTER_NAME);
    greybus_handle = register_dissector(GREYBUS_PROTOCOL_FILTER_NAME, dissect_greybus, proto_greybus);
    proto_register_field_array(proto_greybus, greybus_hf, array_length(greybus_hf));
    proto_register_subtree_array(greybus_ett, array_length(greybus_ett));
    greybus_dissector_table = register_dissector_table(GREYBUS_PROTOCOL_FILTER_NAME ".type", GREYBUS_PROTOCOL_SHORT_NAME " Type", proto_greybus, FT_UINT8, BASE_HEX);
    register_decode_as(&greybus_da);
}

void proto_reg_handoff_greybus(void)
{
	dissector_add_for_decode_as("tcp.port", greybus_handle);
}
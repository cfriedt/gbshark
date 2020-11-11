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

#include <epan/decode_as.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <wsutil/str_util.h>

#include "greybus_types.h"
#include "greybus_manifest.h"
#include "greybus_protocols.h"

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
static int hf_greybus_version_major = -1;
static int hf_greybus_version_minor = -1;
static int hf_greybus_manifest_size = -1;
static int hf_greybus_manifest = -1;
static int hf_greybus_result = -1;
static int hf_greybus_cport_id = -1;

/* Manifest Fields (some above fields reused) */
static int hf_greybus_manifest_desc_size = -1;
static int hf_greybus_manifest_desc_type = -1;
/* Interface Descriptor */
static int hf_greybus_manifest_intf_vendor_string_id = -1;
static int hf_greybus_manifest_intf_product_string_id = -1;
static int hf_greybus_manifest_intf_features = -1;
/* String Descriptor */
static int hf_greybus_manifest_string_id = -1;
static int hf_greybus_manifest_string_length = -1;
static int hf_greybus_manifest_string_value = -1;
/* Bundle Descriptor */
static int hf_greybus_bundle_id = -1;
static int hf_greybus_bundle_class = -1;
/* CPort Descriptor */
static int hf_greybus_cport_protocol = -1;

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
#undef _decl

#define _decl(x) { GREYBUS_TYPE_ ## x, #x }
static const value_string desctypenames[] = {
	_decl(INTERFACE),
	_decl(STRING),
	_decl(BUNDLE),
	_decl(CPORT),
	{ 0, NULL },
};
#undef _decl

#define _decl(x) { GREYBUS_PROTOCOL_ ## x, #x }
static const value_string protocoltypenames[] = {
	_decl(CONTROL),
	_decl(AP),
	_decl(GPIO),
	_decl(I2C),
	_decl(UART),
	_decl(HID),
	_decl(USB),
	_decl(SDIO),
	_decl(POWER_SUPPLY),
	_decl(PWM),
	_decl(SPI),
	_decl(DISPLAY),
	_decl(CAMERA_MGMT),
	_decl(SENSOR),
	_decl(LIGHTS),
	_decl(VIBRATOR),
	_decl(LOOPBACK),
	_decl(AUDIO_MGMT),
	_decl(AUDIO_DATA),
	_decl(SVC),
	_decl(FIRMWARE),
	_decl(CAMERA_DATA),
	_decl(RAW),
	_decl(VENDOR),
	{ 0, NULL },
};
#undef _decl

enum gb_bundle_class {
	GB_BUNDLE_CLASS_CONTROL = 0x00,
	GB_BUNDLE_CLASS_HID = 0x05,
	GB_BUNDLE_CLASS_POWER_SUPPLY = 0x08,
	GB_BUNDLE_CLASS_BRIDGED_PHY = 0x0a,
	GB_BUNDLE_CLASS_DISPLAY = 0x0c,
	GB_BUNDLE_CLASS_CAMERA = 0x0d,
	GB_BUNDLE_CLASS_SENSOR = 0x0e,
	GB_BUNDLE_CLASS_LIGHTS = 0x0f,
	GB_BUNDLE_CLASS_VIBRATOR = 0x10,
	GB_BUNDLE_CLASS_LOOPBACK = 0x11,
	GB_BUNDLE_CLASS_AUDIO = 0x12,
	GB_BUNDLE_CLASS_BOOTROM = 0x15,
	GB_BUNDLE_CLASS_FIRMWARE_MANAGEMENT = 0x16,
	GB_BUNDLE_CLASS_LOG = 0x17,
	GB_BUNDLE_CLASS_RAW = 0xfe,
	GB_BUNDLE_CLASS_VENDOR_SPECIFIC = 0xff,
};

#define _decl(x) { GB_BUNDLE_CLASS_ ## x, #x }
static const value_string classtypenames[] = {
	_decl(CONTROL),
	_decl(HID),
	_decl(POWER_SUPPLY),
	_decl(BRIDGED_PHY),
	_decl(DISPLAY),
	_decl(CAMERA),
	_decl(SENSOR),
	_decl(LIGHTS),
	_decl(VIBRATOR),
	_decl(LOOPBACK),
	_decl(AUDIO),
	_decl(BOOTROM),
	_decl(FIRMWARE_MANAGEMENT),
	_decl(LOG),
	_decl(RAW),
	_decl(VENDOR_SPECIFIC),
	{ 0, NULL },
};
#undef _decl

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
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.data",
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

	/* Manifest Fields */
	{
		&hf_greybus_manifest_desc_size,
		{
			"Descriptor Size",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.desc.size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_manifest_desc_type,
		{
			"Descriptor Type",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.desc.type",
			FT_UINT8, BASE_DEC,
			VALS(desctypenames), 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_manifest_intf_vendor_string_id,
		{
			"Vendor String ID",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.intf.vendor_string_id",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_manifest_intf_product_string_id,
		{
			"Product String ID",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.intf.product_string_id",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_manifest_intf_features,
		{
			"Features",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.intf.features",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_manifest_string_id,
		{
			"String ID",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.string.id",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_manifest_string_length,
		{
			"String Length",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.string.length",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_manifest_string_value,
		{
			"String Value",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.string.value",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_bundle_class,
		{
			"Bundle Class",
			GREYBUS_PROTOCOL_FILTER_NAME ".bundle.class",
			FT_UINT8, BASE_DEC,
			VALS(classtypenames), 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_cport_protocol,
		{
			"CPort Protocol",
			GREYBUS_PROTOCOL_FILTER_NAME ".manifest.cport.protocol",
			FT_UINT8, BASE_NONE,
			VALS(protocoltypenames), 0x0,
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
    offset += 2; /* (padding) */

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
		        proto_tree_add_item(greybus_tree, hf_greybus_manifest_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		        offset += 2;
		        proto_tree_add_item(greybus_tree, hf_greybus_version_major, tvb, offset, 1, ENC_NA);
		        offset += 1;
		        proto_tree_add_item(greybus_tree, hf_greybus_version_minor, tvb, offset, 1, ENC_NA);
		        offset += 1;

			for( ;tvb_captured_length(tvb) - offset > 0; ) {
			        proto_tree_add_item(greybus_tree, hf_greybus_manifest_desc_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			        offset += 2;
				guint8 desc_type = tvb_get_guint8(tvb, offset);
			        proto_tree_add_item(greybus_tree, hf_greybus_manifest_desc_type, tvb, offset, 1, ENC_NA);
			        offset += 1;
				offset += 1; /* (pad) */

				switch(desc_type) {
				case GREYBUS_TYPE_INTERFACE:
				        proto_tree_add_item(greybus_tree, hf_greybus_manifest_intf_vendor_string_id, tvb, offset, 1, ENC_NA);
				        offset += 1;
				        proto_tree_add_item(greybus_tree, hf_greybus_manifest_intf_product_string_id, tvb, offset, 1, ENC_NA);
				        offset += 1;
				        proto_tree_add_item(greybus_tree, hf_greybus_manifest_intf_features, tvb, offset, 1, ENC_NA);
				        offset += 1;
				        offset += 1; /* (pad) */
					break;
				case GREYBUS_TYPE_STRING: {
					guint8 string_length = tvb_get_guint8(tvb, offset);
				        proto_tree_add_item(greybus_tree, hf_greybus_manifest_string_length, tvb, offset, 1, ENC_NA);
				        offset += 1;
				        proto_tree_add_item(greybus_tree, hf_greybus_manifest_string_id, tvb, offset, 1, ENC_NA);
				        offset += 1;
				        proto_tree_add_item(greybus_tree, hf_greybus_manifest_string_value, tvb, offset, string_length, ENC_NA);
					for(offset += string_length; offset % 4 != 0; ++offset);
					} break;
				case GREYBUS_TYPE_BUNDLE:
				        proto_tree_add_item(greybus_tree, hf_greybus_bundle_id, tvb, offset, 1, ENC_NA);
				        offset += 1;
				        proto_tree_add_item(greybus_tree, hf_greybus_bundle_class, tvb, offset, 1, ENC_NA);
				        offset += 1;
					offset += 2; /* (pad) */
					break;
				case GREYBUS_TYPE_CPORT:
				        proto_tree_add_item(greybus_tree, hf_greybus_cport_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				        offset += 2;
				        proto_tree_add_item(greybus_tree, hf_greybus_bundle_id, tvb, offset, 1, ENC_NA);
				        offset += 1;
				        proto_tree_add_item(greybus_tree, hf_greybus_cport_protocol, tvb, offset, 1, ENC_NA);
				        offset += 1;
					break;
				case GREYBUS_TYPE_INVALID:
				default:
					break;
				}
			}
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

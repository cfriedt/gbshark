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
#include "packet-greybus-control.h"

#define GREYBUS_PROTOCOL_SHORT_NAME "Greybus Control"
#define GREYBUS_PROTOCOL_NAME GREYBUS_PROTOCOL_SHORT_NAME " Protocol"
#define GREYBUS_PROTOCOL_FILTER_NAME "greybus.control"

void proto_register_greybus(void);
void proto_reg_handoff_greybus(void);

static gpointer greybus_value(packet_info *pinfo);
static void greybus_prompt(packet_info *pinfo, gchar* result);

static int proto_greybus = -1;

static int hf_greybus_type = -1;

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
static gint ett_greybus_version = -1;
static gint ett_greybus_manifest_size = -1;
static gint ett_greybus_connected = -1;
static gint ett_greybus_bundle_activate = -1;

static gint ett_greybus_manifest = -1;
static gint ett_greybus_manifest_desc = -1;
static gint ett_greybus_manifest_desc_payload = -1;

static gint *greybus_ett[] = {
    &ett_greybus,
    &ett_greybus_version,
    &ett_greybus_manifest_size,
    &ett_greybus_connected,
	&ett_greybus_bundle_activate,

    &ett_greybus_manifest,
    &ett_greybus_manifest_desc,
    &ett_greybus_manifest_desc_payload,
};

static dissector_handle_t greybus_handle;
static dissector_table_t greybus_dissector_table;

#define _decl(x) { GB_CONTROL_TYPE_ ## x, #x }
static const value_string packettypenames[] = {
	{ GB_REQUEST_TYPE_CPORT_SHUTDOWN, "CPORT_SHUTDOWN" },
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
	/* Field for @ref gb_operation_msg_hdr.type
	 * Protocols have overlapping types, so "greybus.op.type"
	 * must be registered separately by each protocol
	 */
	{
		&hf_greybus_type,
		{
			"Message Type",
			"greybus.op.type",
			FT_UINT8, BASE_DEC,
			VALS(packettypenames), ~GB_OP_RESPONSE_MASK,
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

static guint greybus_dissect_version(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
    (void) pinfo;
    // request and response are identical
    struct gb_control_bundle_version_response response;
    guint offset = sizeof(*header);
    guint nread = 0;
    proto_tree  *payload_tree;

    if (tvb_bytes_exist(tvb, offset, sizeof(response))) {
        response.major = tvb_get_guint8(tvb, offset);
        response.minor = tvb_get_guint8(tvb, offset + 1);
        payload_tree = proto_tree_add_subtree_format(greybus_tree, tvb, offset, sizeof(response), ett_greybus_version, NULL,
            "Version %u.%u", response.major, response.minor);
        proto_tree_add_uint(payload_tree, hf_greybus_version_major, tvb, offset, 1, response.major);
        proto_tree_add_uint(payload_tree, hf_greybus_version_minor, tvb, offset + 1, 1, response.minor);
        nread += sizeof(response);
    } else {
        // indicate somehow that there is a malformed packet?
    }

    return nread;
}

static guint greybus_dissect_manifest_size(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
    (void) pinfo;
    guint offset = sizeof(*header);
    guint nread = 0;
    proto_tree  *payload_tree;

    if (gb_op_is_response(header)) {
        struct gb_control_get_manifest_size_response response;
        if (tvb_bytes_exist(tvb, offset, sizeof(response))) {
            response.size = tvb_get_letohs(tvb, offset);
            payload_tree = proto_tree_add_subtree_format(greybus_tree, tvb, offset, sizeof(response), ett_greybus_manifest_size, NULL,
                "Manifest Size %u", response.size);
            proto_tree_add_uint(payload_tree, hf_greybus_manifest_size, tvb, offset, 2, response.size);
            nread += sizeof(response);
        } else {
            // indicate somehow that there is a malformed packet?
        }
    }

    return nread;
}

static void greybus_dissect_manifest(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
    (void) pinfo;
    guint offset = sizeof(*header);
    proto_tree  *payload_tree;
    proto_tree  *descriptor_tree;
    proto_tree  *descriptor_payload_tree;

    uint16_t nbundle = 0;
    uint16_t ncport = 0;
    uint16_t nstr = 0;
    uint16_t ninterface = 0;
    //bool control = false;

    if (gb_op_is_response(header)) {
        struct greybus_manifest_header manifest_header;

        if (!tvb_bytes_exist(tvb, offset, sizeof(manifest_header))) {
            // indicate somehow that there is a malformed packet?
            printf("%s(): %d\n", __func__, __LINE__);
            return;
        }

        manifest_header.size = tvb_get_letohs(tvb, offset);
        manifest_header.version_major = tvb_get_guint8(tvb, offset + 2);
        manifest_header.version_minor = tvb_get_guint8(tvb, offset + 3);
        payload_tree = proto_tree_add_subtree_format(greybus_tree, tvb, offset, sizeof(manifest_header), ett_greybus_manifest_size, NULL,
            "Manifest. Size: %u Version: %u.%u", manifest_header.size, manifest_header.version_major, manifest_header.version_minor);
        proto_tree_add_uint(payload_tree, hf_greybus_manifest_size, tvb, offset, 2, manifest_header.size);
	    proto_tree_add_uint(payload_tree, hf_greybus_version_major, tvb, offset + 2, 1, manifest_header.version_major);
        proto_tree_add_uint(payload_tree, hf_greybus_version_minor, tvb, offset + 1, 1, manifest_header.version_minor);
        offset += sizeof(manifest_header);

        if (!tvb_bytes_exist(tvb, offset, manifest_header.size - sizeof(manifest_header))) {
            // indicate somehow that there is a malformed packet?
            printf("%s(): %d\n", __func__, __LINE__);
            return;
        }

        for( ;tvb_captured_length(tvb) - offset > 0; ) {
            struct greybus_descriptor descriptor;
            if (!tvb_bytes_exist(tvb, offset, sizeof(descriptor.header))) {
                // indicate somehow that there is a malformed packet?
                printf("%s(): %d\n", __func__, __LINE__);
                return;
            }

            descriptor.header.size = tvb_get_letohs(tvb, offset);
            descriptor.header.type = tvb_get_guint8(tvb, offset + 2);
            descriptor.header.pad = tvb_get_guint8(tvb, offset + 3);
            descriptor_tree = proto_tree_add_subtree_format(payload_tree, tvb, offset, descriptor.header.size,
                ett_greybus_manifest_desc, NULL, "Descriptor Size: %u Type: %s", descriptor.header.size,
                val_to_str(descriptor.header.type, desctypenames, "Unknown (0x%02x)"));
            proto_tree_add_uint(descriptor_tree, hf_greybus_manifest_desc_size, tvb, offset, 2, descriptor.header.size);
            proto_tree_add_uint(descriptor_tree, hf_greybus_manifest_desc_type, tvb, offset + 2, 1, descriptor.header.type);
            proto_tree_add_bytes(descriptor_tree, hf_greybus_pad, tvb, offset + 3, 1, &descriptor.header.pad);
            offset += sizeof(descriptor.header);

            if (!tvb_bytes_exist(tvb, offset, descriptor.header.size - sizeof(descriptor.header))) {
                // indicate somehow that there is a malformed packet?
                printf("%s(): %d\n", __func__, __LINE__);
                return;
            }

   			switch(descriptor.header.type) {
			case GREYBUS_TYPE_INTERFACE: {
                ninterface++;
                struct greybus_descriptor_interface iface_desc;

                iface_desc.vendor_stringid = tvb_get_guint8(tvb, offset);
                iface_desc.product_stringid = tvb_get_guint8(tvb, offset + 1);
                tvb_memcpy(tvb, iface_desc.pad, offset + 2, sizeof(iface_desc.pad));

                descriptor_payload_tree = proto_tree_add_subtree_format(descriptor_tree, tvb, offset, sizeof(iface_desc),
                    ett_greybus_manifest_desc_payload, NULL, "Vendor String ID: %u Product String ID: %u",
                    iface_desc.vendor_stringid, iface_desc.product_stringid);

	            proto_tree_add_uint(descriptor_payload_tree, hf_greybus_manifest_intf_vendor_string_id, tvb, offset, 1,
                    iface_desc.vendor_stringid);
	            proto_tree_add_uint(descriptor_payload_tree, hf_greybus_manifest_intf_vendor_string_id, tvb, offset + 1, 1,
                    iface_desc.product_stringid);
	            proto_tree_add_bytes(descriptor_payload_tree, hf_greybus_pad, tvb, offset + 2, sizeof(iface_desc.pad),
                    iface_desc.pad);
                offset += sizeof(iface_desc);
   				} break;
			case GREYBUS_TYPE_STRING: {
                nstr++;
                struct greybus_descriptor_string string_desc;

                string_desc.length = tvb_get_guint8(tvb, offset);
                string_desc.id = tvb_get_guint8(tvb, offset + 1);

                /* TODO: copy this into a buffer so that it can be displayed in the format area */
                descriptor_payload_tree = proto_tree_add_subtree_format(descriptor_tree, tvb, offset, sizeof(string_desc),
                    ett_greybus_manifest_desc_payload, NULL, "String: Length: %u ID: %u",
                    string_desc.length, string_desc.id);

	            proto_tree_add_uint(descriptor_payload_tree, hf_greybus_manifest_string_length, tvb, offset, 1, string_desc.length);
   		        proto_tree_add_uint(descriptor_payload_tree, hf_greybus_manifest_string_id, tvb, offset + 1, 1, string_desc.id);
                proto_tree_add_item(descriptor_payload_tree, hf_greybus_manifest_string_value, tvb, offset + 2, string_desc.length, ENC_NA);
                offset += sizeof(string_desc) + string_desc.length;
                if (offset % 4 != 0) {
                    proto_tree_add_item(descriptor_payload_tree, hf_greybus_pad, tvb, offset, 4 - (offset % 4), ENC_NA);
                    offset += 4 - (offset % 4);
                }
                } break;
    		case GREYBUS_TYPE_BUNDLE: {
                nbundle++;
                struct greybus_descriptor_bundle bundle_desc;

                bundle_desc.id = tvb_get_guint8(tvb, offset);
                bundle_desc.class_ = tvb_get_guint8(tvb, offset + 1);
                tvb_memcpy(tvb, bundle_desc.pad, offset + 2, sizeof(bundle_desc.pad));

                descriptor_payload_tree = proto_tree_add_subtree_format(descriptor_tree, tvb, offset, sizeof(bundle_desc),
                    ett_greybus_manifest_desc_payload, NULL, "Bundle: ID: %u class: %s",
                    bundle_desc.id, val_to_str(bundle_desc.class_, classtypenames, "Unknown (0x%02x)"));

		        proto_tree_add_item(descriptor_payload_tree, hf_greybus_bundle_id, tvb, offset, 1, ENC_NA);
		        proto_tree_add_item(descriptor_payload_tree, hf_greybus_bundle_class, tvb, offset + 1, 1, ENC_NA);
                proto_tree_add_bytes(descriptor_payload_tree, hf_greybus_pad, tvb, offset + 2, 2, bundle_desc.pad);
                offset += sizeof(bundle_desc);
   				} break;
			case GREYBUS_TYPE_CPORT: {
                ncport++;
                struct greybus_descriptor_cport cport_desc;

                cport_desc.id = tvb_get_letohs(tvb, offset);
                cport_desc.bundle = tvb_get_guint8(tvb, offset + 2);
                cport_desc.protocol_id = tvb_get_guint8(tvb, offset + 3);

#if 0
                if (cport_desc.id == 0 && cport_desc.bundle == 0 && cport_desc.protocol_id == 0) {
                    if (control) {
                        // indicate somehow that there is a malformed packet?
                        return;
                    } else {
                        control = true;
                    }
                }
#endif

                descriptor_payload_tree = proto_tree_add_subtree_format(descriptor_tree, tvb, offset, sizeof(cport_desc),
                    ett_greybus_manifest_desc_payload, NULL, "CPort: ID: %u Bundle: %u Protocol: %s",
                    cport_desc.id, cport_desc.bundle, val_to_str(cport_desc.protocol_id, protocoltypenames, "Unknown (0x%02x)"));

                proto_tree_add_uint(descriptor_payload_tree, hf_greybus_cport_id, tvb, offset, 2, cport_desc.id);
	            proto_tree_add_uint(descriptor_payload_tree, hf_greybus_bundle_id, tvb, offset + 2, 1, cport_desc.bundle);
    	        proto_tree_add_uint(descriptor_payload_tree, hf_greybus_cport_protocol, tvb, offset + 3, 1, cport_desc.protocol_id);
                offset += sizeof(cport_desc);
 				} break;
   		    case GREYBUS_TYPE_INVALID:
	    	default: {
                printf("invalid descriptor %u\n", descriptor.header.type);
                uint8_t unknown_desc_size = descriptor.header.size - sizeof(descriptor.header);
                descriptor_payload_tree = proto_tree_add_subtree_format(descriptor_tree, tvb, offset, unknown_desc_size,
                    ett_greybus_manifest_desc_payload, NULL, "Unknown Descriptor");
                offset += unknown_desc_size;
    			} break;
   			}
        }

#if 0
        if (ninterface != 1) {
            // indicate somehow that there is a malformed packet?
            return;
        }

        if (nstr < 2) {
            // indicate somehow that there is a malformed packet?
            return;
        }

        /* TODO: append additional data to a higher-level tree item so fewer subtree expansions are required */
        //proto_item_append_text(ti, ", Type %s", val_to_str(header->type & ~GB_OP_RESPONSE_MASK, packettypenames, "Unknown (0x%02x)"));
#endif
    }
}

/* this is used for both connect and disconnect */
static void greybus_dissect_connected(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
    (void) pinfo;
    guint offset = sizeof(*header);
    struct gb_control_connected_request request;
    proto_tree *payload_tree;

    if (!gb_op_is_response(header)) {
        if (tvb_bytes_exist(tvb, offset, sizeof(request))) {
            request.cport_id = tvb_get_letohs(tvb, offset);
            payload_tree = proto_tree_add_subtree_format(greybus_tree, tvb, offset, sizeof(request), ett_greybus_connected, NULL,
                "%s: CPort ID %u", val_to_str(header->type & ~GB_OP_RESPONSE_MASK, packettypenames, "Unknown (0x%02x)"), request.cport_id);
    		proto_tree_add_uint(payload_tree, hf_greybus_cport_id, tvb, offset, 2, request.cport_id);
	    	offset += sizeof(request);
        } else {
            // indicate somehow that there is a malformed packet?
        }
	}
}

/* this is used for all bundle power management operations */
static void greybus_dissect_bundle_activate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	(void) pinfo;
    guint offset = sizeof(*header);
    // same message structure is used for
    proto_tree *payload_tree;

    if (gb_op_is_response(header)) {
        struct gb_control_bundle_pm_response response;
        if (tvb_bytes_exist(tvb, offset, sizeof(response))) {
            response.status = tvb_get_guint8(tvb, offset);
            payload_tree = proto_tree_add_subtree_format(greybus_tree, tvb, offset, sizeof(response), ett_greybus_bundle_activate, NULL,
                "%s: Status %u", val_to_str(header->type & ~GB_OP_RESPONSE_MASK, packettypenames, "Unknown (0x%02x)"), response.status);
    		proto_tree_add_uint(payload_tree, hf_greybus_result, tvb, offset, 1, response.status);
	    	offset += sizeof(response);
        } else {
            // indicate somehow that there is a malformed packet?
        }
    } else {
        struct gb_control_bundle_pm_request request;
        if (tvb_bytes_exist(tvb, offset, sizeof(request))) {
            request.bundle_id = tvb_get_guint8(tvb, offset);
            payload_tree = proto_tree_add_subtree_format(greybus_tree, tvb, offset, sizeof(request), ett_greybus_bundle_activate, NULL,
                "%s: Bundle ID %u", val_to_str(header->type & ~GB_OP_RESPONSE_MASK, packettypenames, "Unknown (0x%02x)"), request.bundle_id);
    		proto_tree_add_uint(payload_tree, hf_greybus_bundle_id, tvb, offset, 1, request.bundle_id);
	    	offset += sizeof(request);
        } else {
            // indicate somehow that there is a malformed packet?
        }
	}
}

static void greybus_dissect_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	switch(gb_op_get_type(header)) {
	case GB_REQUEST_TYPE_CPORT_SHUTDOWN:
		greybus_dissect_cport_shutdown(tvb, pinfo, ett_greybus, greybus_tree, header);
		break;
	case GB_CONTROL_TYPE_VERSION:
		greybus_dissect_version(tvb, pinfo, greybus_tree, header);
		break;
	case GB_CONTROL_TYPE_GET_MANIFEST_SIZE:
		greybus_dissect_manifest_size(tvb, pinfo, greybus_tree, header);
		break;
	case GB_CONTROL_TYPE_GET_MANIFEST:
		greybus_dissect_manifest(tvb, pinfo, greybus_tree, header);
		break;
	case GB_CONTROL_TYPE_CONNECTED:
	case GB_CONTROL_TYPE_DISCONNECTED:
	case GB_CONTROL_TYPE_DISCONNECTING:
        greybus_dissect_connected(tvb, pinfo, greybus_tree, header);
		break;
	case GB_CONTROL_TYPE_BUNDLE_SUSPEND:
	case GB_CONTROL_TYPE_BUNDLE_RESUME:
	case GB_CONTROL_TYPE_BUNDLE_ACTIVATE:
	case GB_CONTROL_TYPE_BUNDLE_DEACTIVATE:
        greybus_dissect_bundle_activate(tvb, pinfo, greybus_tree, header);
		break;
	case GB_CONTROL_TYPE_INTF_SUSPEND_PREPARE:
		break;
	case GB_CONTROL_TYPE_INTF_DEACTIVATE_PREPARE:
		break;
	case GB_CONTROL_TYPE_INTF_HIBERNATE_ABORT:
		break;

	/* Timesync not used in practise */
	case GB_CONTROL_TYPE_TIMESYNC_GET_LAST_EVENT:
	case GB_CONTROL_TYPE_TIMESYNC_ENABLE:
	case GB_CONTROL_TYPE_TIMESYNC_DISABLE:
	case GB_CONTROL_TYPE_TIMESYNC_AUTHORITATIVE:

	/* Not in the spec */
	case GB_CONTROL_TYPE_PROBE_AP:

	/* Unhandled so far */
	case GB_CONTROL_TYPE_BUNDLE_VERSION:
	case GB_CONTROL_TYPE_MODE_SWITCH:
	default:
		break;
    }
}

static int
dissect_greybus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_tree *greybus_tree = NULL;
    struct gb_operation_msg_hdr header = {};

    if (!greybus_dissect_header(tvb, pinfo, proto_greybus, ett_greybus, tree, &greybus_tree, &header, GREYBUS_PROTOCOL_NAME, packettypenames, hf_greybus_type)) {
    	goto out;
    }

    greybus_dissect_payload(tvb, pinfo, greybus_tree, &header);

out:
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
    proto_register_field_array(proto_greybus, greybus_common_hf, greybus_common_hf_size);
    proto_register_subtree_array(greybus_ett, array_length(greybus_ett));
    greybus_dissector_table = register_dissector_table(GREYBUS_PROTOCOL_FILTER_NAME ".type", GREYBUS_PROTOCOL_SHORT_NAME " Type", proto_greybus, FT_UINT8, BASE_HEX);
    register_decode_as(&greybus_da);
}

void proto_reg_handoff_greybus(void)
{
	dissector_add_for_decode_as("tcp.port", greybus_handle);
}

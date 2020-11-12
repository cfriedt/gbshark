/* packet-greybus-gpio.c
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

#include "greybus/greybus_types.h"
#include "greybus/greybus_protocols.h"

#include "packet-greybus-common.h"
#include "packet-greybus-gpio.h"

#define GREYBUS_PROTOCOL_SHORT_NAME "Greybus GPIO"
#define GREYBUS_PROTOCOL_NAME GREYBUS_PROTOCOL_SHORT_NAME " Protocol"
#define GREYBUS_PROTOCOL_FILTER_NAME "greybus.gpio"

void proto_register_greybus(void);
void proto_reg_handoff_greybus(void);

static gpointer greybus_value(packet_info *pinfo);
static void greybus_prompt(packet_info *pinfo, gchar* result);

static int proto_greybus = -1;

static int hf_greybus_type = -1;
static int hf_greybus_gpio_line_count = -1;
static int hf_greybus_gpio_which = -1;
static int hf_greybus_gpio_direction = -1;
static int hf_greybus_gpio_value = -1;
static int hf_greybus_gpio_usec = -1;
static int hf_greybus_gpio_irq_type = -1;

static gint ett_greybus = -1;
static dissector_handle_t greybus_handle;
static const true_false_string in_out = { "In", "Out" };
static dissector_table_t greybus_dissector_table;

#define _decl(x) { GB_GPIO_TYPE_ ## x, #x }
static const value_string packettypenames[] = {
	{ GB_REQUEST_TYPE_CPORT_SHUTDOWN, "CPORT_SHUTDOWN" },
	_decl(LINE_COUNT),
	_decl(ACTIVATE),
	_decl(DEACTIVATE),
	_decl(GET_DIRECTION),
	_decl(DIRECTION_IN),
	_decl(DIRECTION_OUT),
	_decl(GET_VALUE),
	_decl(SET_VALUE),
	_decl(SET_DEBOUNCE),
	_decl(IRQ_TYPE),
	_decl(IRQ_MASK),
	_decl(IRQ_UNMASK),
	_decl(IRQ_EVENT),
	{ 0, NULL },
};
#undef _decl

#define _decl(x) { GB_GPIO_IRQ_TYPE_ ## x, #x }
static const value_string irqtypes[] = {
	_decl(NONE),
	_decl(EDGE_RISING),
	_decl(EDGE_FALLING),
	_decl(EDGE_BOTH),
	_decl(LEVEL_HIGH),
	_decl(LEVEL_LOW),
	{ 0, NULL },
};
#undef _decl

static hf_register_info greybus_hf[] = {
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
		&hf_greybus_gpio_line_count,
		{
			"Line count",
			GREYBUS_PROTOCOL_FILTER_NAME ".line_count",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_gpio_which,
		{
			"Which",
			GREYBUS_PROTOCOL_FILTER_NAME ".which",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_gpio_direction,
		{
			"Direction",
			GREYBUS_PROTOCOL_FILTER_NAME ".direction",
			FT_BOOLEAN, 8,
			TFS(&in_out), 0x01,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_gpio_value,
		{
			"Value",
			GREYBUS_PROTOCOL_FILTER_NAME ".value",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_gpio_usec,
		{
			"Microseconds",
			GREYBUS_PROTOCOL_FILTER_NAME ".usec",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_gpio_irq_type,
		{
			"IRQ Type",
			GREYBUS_PROTOCOL_FILTER_NAME ".irq.type",
			FT_UINT8, BASE_DEC,
			VALS(irqtypes), ~0xf,
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

static void greybus_dissect_line_count(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void)pinfo;
	if (gb_op_is_response(header)) {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_line_count, tvb, offset, 1, ENC_NA);
        offset += 1;
	}
}

static void greybus_dissect_activate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void)pinfo;
	if (!gb_op_is_response(header)) {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_which, tvb, offset, 1, ENC_NA);
        offset += 1;
	}
}

static void greybus_dissect_get_direction(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void)pinfo;
	if (gb_op_is_response(header)) {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_direction, tvb, offset, 1, ENC_NA);
        offset += 1;
	} else {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_which, tvb, offset, 1, ENC_NA);
        offset += 1;
	}
}

static void greybus_dissect_direction_in(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void)pinfo;
	if (!gb_op_is_response(header)) {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_which, tvb, offset, 1, ENC_NA);
        offset += 1;
	}
}

static void greybus_dissect_direction_out(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void)pinfo;
	if (!gb_op_is_response(header)) {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_which, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_value, tvb, offset, 1, ENC_NA);
        offset += 1;
	}
}

static void greybus_dissect_get_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void)pinfo;
	if (gb_op_is_response(header)) {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_value, tvb, offset, 1, ENC_NA);
        offset += 1;
	} else {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_which, tvb, offset, 1, ENC_NA);
        offset += 1;
	}
}

static void greybus_dissect_set_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void)pinfo;
	if (!gb_op_is_response(header)) {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_which, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_value, tvb, offset, 1, ENC_NA);
        offset += 1;
	}
}

static void greybus_dissect_set_debounce(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void)pinfo;
	if (!gb_op_is_response(header)) {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_which, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_usec, tvb, offset, 2, ENC_NA);
        offset += 2;
	}
}

static void greybus_dissect_irq_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void)pinfo;
	if (!gb_op_is_response(header)) {
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_which, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(greybus_tree, hf_greybus_gpio_irq_type, tvb, offset, 1, ENC_NA);
        offset += 1;
	}
}

static void greybus_dissect_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	switch(gb_op_get_type(header)) {
	case GB_REQUEST_TYPE_CPORT_SHUTDOWN:
		greybus_dissect_cport_shutdown(tvb, pinfo, ett_greybus, greybus_tree, header);
		break;
    case GB_GPIO_TYPE_LINE_COUNT:
    	greybus_dissect_line_count(tvb, pinfo, greybus_tree, header);
		break;
    case GB_GPIO_TYPE_ACTIVATE:
    case GB_GPIO_TYPE_DEACTIVATE:
    	greybus_dissect_activate(tvb, pinfo, greybus_tree, header);
    	break;
    case GB_GPIO_TYPE_GET_DIRECTION:
    	greybus_dissect_get_direction(tvb, pinfo, greybus_tree, header);
    	break;
    case GB_GPIO_TYPE_DIRECTION_OUT:
    	greybus_dissect_direction_out(tvb, pinfo, greybus_tree, header);
    	break;
    case GB_GPIO_TYPE_GET_VALUE:
    	greybus_dissect_get_value(tvb, pinfo, greybus_tree, header);
    	break;
    case GB_GPIO_TYPE_SET_VALUE:
    	greybus_dissect_set_value(tvb, pinfo, greybus_tree, header);
    	break;
    case GB_GPIO_TYPE_SET_DEBOUNCE:
    	greybus_dissect_set_debounce(tvb, pinfo, greybus_tree, header);
    	break;
    case GB_GPIO_TYPE_IRQ_TYPE:
    	greybus_dissect_irq_type(tvb, pinfo, greybus_tree, header);
    	break;
    case GB_GPIO_TYPE_IRQ_MASK:
    case GB_GPIO_TYPE_IRQ_UNMASK:
    case GB_GPIO_TYPE_IRQ_EVENT:
    case GB_GPIO_TYPE_DIRECTION_IN:
    	greybus_dissect_direction_in(tvb, pinfo, greybus_tree, header);
    	break;
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

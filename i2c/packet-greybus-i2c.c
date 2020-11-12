/* packet-greybus-i2c.c
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
#include "greybus_protocols.h"

#include "packet-greybus-i2c.h"

#define GREYBUS_PROTOCOL_SHORT_NAME "Greybus I2C"
#define GREYBUS_PROTOCOL_NAME GREYBUS_PROTOCOL_SHORT_NAME " Protocol"
#define GREYBUS_PROTOCOL_FILTER_NAME "greybus.i2c"

enum i2c_func {
	I2C_FUNC_I2C = 0x00000001,
	I2C_FUNC_10BIT_ADDR = 0x00000002,
	I2C_FUNC_SMBUS_PEC = 0x00000008,
	I2C_FUNC_NOSTART = 0x00000010,
	I2C_FUNC_SMBUS_BLOCK_PROC_CALL = 0x00008000,
	I2C_FUNC_SMBUS_QUICK = 0x00010000,
	I2C_FUNC_SMBUS_READ_BYTE = 0x00020000,
	I2C_FUNC_SMBUS_WRITE_BYTE = 0x00040000,
	I2C_FUNC_SMBUS_READ_BYTE_DATA = 0x00080000,
	I2C_FUNC_SMBUS_WRITE_BYTE_DATA = 0x00100000,
	I2C_FUNC_SMBUS_READ_WORD_DATA = 0x00200000,
	I2C_FUNC_SMBUS_WRITE_WORD_DATA = 0x00400000,
	I2C_FUNC_SMBUS_PROC_CALL = 0x00800000,
	I2C_FUNC_SMBUS_READ_BLOCK_DATA = 0x00800000,
	I2C_FUNC_SMBUS_WRITE_BLOCK_DATA = 0x01000000,
	I2C_FUNC_SMBUS_READ_I2C_BLOCK = 0x02000000,
	I2C_FUNC_SMBUS_WRITE_I2C_BLOCK = 0x04000000,
};

enum i2c_transfer_flag {
	I2C_M_RD = 0x0001,
	I2C_M_TEN = 0x0010,
	I2C_M_RECV_LEN = 0x0400,
	I2C_M_NOSTART = 0x8000,
};

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
static int hf_greybus_result = -1;
static int hf_greybus_i2c_functionality = -1;
static int hf_greybus_i2c_transfer_op_count = -1;
static int hf_greybus_i2c_transfer_addr = -1;
static int hf_greybus_i2c_transfer_flags = -1;
static int hf_greybus_i2c_transfer_size = -1;
static int hf_greybus_i2c_transfer_data = -1;

/* Functionality Flags */
static int hf_greybus_i2c_func_i2c = -1;
static int hf_greybus_i2c_func_10bit_addr = -1;
static int hf_greybus_i2c_func_smbus_pec = -1;
static int hf_greybus_i2c_func_nostart = -1;
static int hf_greybus_i2c_func_smbus_block_proc_call = -1;
static int hf_greybus_i2c_func_smbus_quick = -1;
static int hf_greybus_i2c_func_smbus_read_byte = -1;
static int hf_greybus_i2c_func_smbus_write_byte = -1;
static int hf_greybus_i2c_func_smbus_read_byte_data = -1;
static int hf_greybus_i2c_func_smbus_write_byte_data = -1;
static int hf_greybus_i2c_func_smbus_read_word_data = -1;
static int hf_greybus_i2c_func_smbus_write_word_data = -1;
static int hf_greybus_i2c_func_smbus_proc_call = -1;
static int hf_greybus_i2c_func_smbus_read_block_data = -1;
static int hf_greybus_i2c_func_smbus_write_block_data = -1;
static int hf_greybus_i2c_func_smbus_read_i2c_block = -1;
static int hf_greybus_i2c_func_smbus_write_i2c_block = -1;
static const int *hf_greybus_i2c_func_bits[] = {
	&hf_greybus_i2c_func_i2c,
	&hf_greybus_i2c_func_10bit_addr,
	&hf_greybus_i2c_func_smbus_pec,
	&hf_greybus_i2c_func_nostart,
	&hf_greybus_i2c_func_smbus_block_proc_call,
	&hf_greybus_i2c_func_smbus_quick,
	&hf_greybus_i2c_func_smbus_read_byte,
	&hf_greybus_i2c_func_smbus_write_byte,
	&hf_greybus_i2c_func_smbus_read_byte_data,
	&hf_greybus_i2c_func_smbus_write_byte_data,
	&hf_greybus_i2c_func_smbus_read_word_data,
	&hf_greybus_i2c_func_smbus_write_word_data,
	&hf_greybus_i2c_func_smbus_proc_call,
	&hf_greybus_i2c_func_smbus_read_block_data,
	&hf_greybus_i2c_func_smbus_write_block_data,
	&hf_greybus_i2c_func_smbus_read_i2c_block,
	&hf_greybus_i2c_func_smbus_write_i2c_block,
	NULL,
};

/* Transfer Flags */
static int hf_greybus_i2c_transfer_flag_rd = -1;
static int hf_greybus_i2c_transfer_flag_ten = -1;
static int hf_greybus_i2c_transfer_flag_recv_len = -1;
static int hf_greybus_i2c_transfer_flag_nostart = -1;
static const int *hf_greybus_i2c_transfer_flags_bits[] = {
	&hf_greybus_i2c_transfer_flag_rd,
	&hf_greybus_i2c_transfer_flag_ten,
	&hf_greybus_i2c_transfer_flag_recv_len,
	&hf_greybus_i2c_transfer_flag_nostart,
	NULL,
};

static gint ett_greybus = -1;
static dissector_handle_t greybus_handle;
static const true_false_string true_false = { "True", "False" };
static dissector_table_t greybus_dissector_table;

#define _decl(x) { GB_I2C_TYPE_ ## x, #x }
static const value_string packettypenames[] = {
	_decl(FUNCTIONALITY),
	_decl(TRANSFER),
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
		&hf_greybus_i2c_functionality,
		{
			"Functionality",
			GREYBUS_PROTOCOL_FILTER_NAME ".functionality",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_i2c_transfer_op_count,
		{
			"Operation Count",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.op_count",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_i2c_transfer_addr,
		{
			"Transfer Address",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.addr",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_i2c_transfer_flags,
		{
			"Transfer Flags",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.flags",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_i2c_transfer_size,
		{
			"Transfer Size",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.size",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_i2c_transfer_data,
		{
			"Transfer Data",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.data",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	/* Functionality Flags */
	{
		&hf_greybus_i2c_func_i2c,
		{
			"I2C",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.i2c",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_I2C,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_10bit_addr,
		{
			"10BIT_ADDR",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.10bit_addr",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_10BIT_ADDR,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_pec,
		{
			"SMBUS_PEC",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_pec",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_PEC,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_nostart,
		{
			"NOSTART",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.nostart",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_NOSTART,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_block_proc_call,
		{
			"SMBUS_BLOCK_PROC_CALL",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_block_proc_call",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_BLOCK_PROC_CALL,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_quick,
		{
			"SMBUS_QUICK",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_quick",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_QUICK,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_read_byte,
		{
			"SMBUS_READ_BYTE",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_read_byte",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_READ_BYTE,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_write_byte,
		{
			"SMBUS_WRITE_BYTE",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_write_byte",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_WRITE_BYTE,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_read_byte_data,
		{
			"SMBUS_READ_BYTE_DATA",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_read_byte_data",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_READ_BYTE_DATA,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_write_byte_data,
		{
			"SMBUS_WRITE_BYTE_DATA",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_write_byte_data",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_WRITE_BYTE_DATA,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_read_word_data,
		{
			"SMBUS_READ_WORD_DATA",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_read_word_data",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_READ_WORD_DATA,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_write_word_data,
		{
			"SMBUS_WRITE_WORD_DATA",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_write_word_data",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_WRITE_WORD_DATA,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_proc_call,
		{
			"SMBUS_PROC_CALL",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_proc_call",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_PROC_CALL,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_read_block_data,
		{
			"SMBUS_READ_BLOCK_DATA",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_read_block_data",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_READ_BLOCK_DATA,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_write_block_data,
		{
			"SMBUS_WRITE_BLOCK_DATA",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_write_block_data",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_WRITE_BLOCK_DATA,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_read_i2c_block,
		{
			"SMBUS_READ_I2C_BLOCK",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_read_i2c_block",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_READ_I2C_BLOCK,
			NULL, HFILL,
		},
	},{
		&hf_greybus_i2c_func_smbus_write_i2c_block,
		{
			"SMBUS_WRITE_I2C_BLOCK",
			GREYBUS_PROTOCOL_FILTER_NAME ".func.smbus_write_i2c_block",
			FT_BOOLEAN, 32,
			NULL, I2C_FUNC_SMBUS_WRITE_I2C_BLOCK,
			NULL, HFILL,
		},
	},

	/* Transfer Flags */
	{
		&hf_greybus_i2c_transfer_flag_rd,
		{
			"I2C_M_RD",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.flag.rd",
			FT_BOOLEAN, 16,
			NULL, I2C_M_RD,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_i2c_transfer_flag_ten,
		{
			"I2C_M_TEN",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.flag.ten",
			FT_BOOLEAN, 16,
			NULL, I2C_M_TEN,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_i2c_transfer_flag_recv_len,
		{
			"I2C_M_RECV_LEN",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.flag.recv_len",
			FT_BOOLEAN, 16,
			NULL, I2C_M_RECV_LEN,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_i2c_transfer_flag_nostart,
		{
			"I2C_M_NOSTART",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.flag.nostart",
			FT_BOOLEAN, 16,
			NULL, I2C_M_NOSTART,
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
	size_t remaining = 0;
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
    offset += 2; /* padding */

    switch(packet_type) {
    case GB_I2C_TYPE_FUNCTIONALITY:
    	if (response) {
			proto_tree_add_bitmask(greybus_tree, tvb, offset, hf_greybus_i2c_functionality, ett_greybus, hf_greybus_i2c_func_bits, ENC_LITTLE_ENDIAN);
            offset += 4;
    	}
    	break;
    case GB_I2C_TYPE_TRANSFER:
    	if (response) {
			remaining = tvb_captured_length(tvb) - offset;
			proto_tree_add_item(greybus_tree, hf_greybus_i2c_transfer_data, tvb, offset, remaining, ENC_NA);
			offset += remaining;
    	} else {

    		guint16 op_count = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(greybus_tree, hf_greybus_i2c_transfer_op_count, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			gint data_offset = offset + 6 * op_count;

			for(uint16_t i = 0; i < op_count; ++i) {

				proto_tree_add_item(greybus_tree, hf_greybus_i2c_transfer_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;
				guint16 flags = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
				proto_tree_add_bitmask(greybus_tree, tvb, offset, hf_greybus_i2c_transfer_flags, ett_greybus, hf_greybus_i2c_transfer_flags_bits, ENC_LITTLE_ENDIAN);
				offset += 2;
				proto_tree_add_item(greybus_tree, hf_greybus_i2c_transfer_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
				guint16 sz = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
				offset += 2;

				if (sz > 0 && !(flags & I2C_M_RD)) {
					proto_tree_add_item(greybus_tree, hf_greybus_i2c_transfer_data, tvb, data_offset, sz, ENC_NA);
					data_offset += sz;
				}
			}
    	}
    	break;
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

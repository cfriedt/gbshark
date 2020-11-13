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
#include "packet-greybus-spi.h"

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

#define GREYBUS_PROTOCOL_SHORT_NAME "Greybus SPI"
#define GREYBUS_PROTOCOL_NAME GREYBUS_PROTOCOL_SHORT_NAME " Protocol"
#define GREYBUS_PROTOCOL_FILTER_NAME "greybus.spi"

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

/* SPI Config */
static int hf_greybus_spi_config_bpw_mask = -1;
static int hf_greybus_spi_config_min_speed_hz = -1;
static int hf_greybus_spi_config_max_speed_hz = -1;
static int hf_greybus_spi_config_mode = -1;
static int hf_greybus_spi_config_flags = -1;
static int hf_greybus_spi_config_num_chipselect = -1;
static int hf_greybus_spi_config_chip_select = -1;
static int hf_greybus_spi_config_bpw = -1;
static int hf_greybus_spi_config_device_type = -1;
static int hf_greybus_spi_config_name = -1;

/* SPI Protocol Flags */
static int hf_greybus_spi_config_flag_half_duplex = -1;
static int hf_greybus_spi_config_flag_no_rx = -1;
static int hf_greybus_spi_config_flag_no_tx = -1;
static const int *hf_greybus_spi_config_flag_bits[] = {
	&hf_greybus_spi_config_flag_half_duplex,
	&hf_greybus_spi_config_flag_no_rx,
	&hf_greybus_spi_config_flag_no_tx,
	NULL,
};

/* SPI Transfer */
static int hf_greybus_spi_transfer_chip_select = -1;
static int hf_greybus_spi_transfer_mode = -1;
static int hf_greybus_spi_transfer_count = -1;
static int hf_greybus_spi_transfer_data = -1;

static int hf_greybus_spi_transfer_speed_hz = -1;
static int hf_greybus_spi_transfer_len = -1;
static int hf_greybus_spi_transfer_delay_usecs = -1;
static int hf_greybus_spi_transfer_cs_change = -1;
static int hf_greybus_spi_transfer_bits_per_word = -1;
static int hf_greybus_spi_transfer_xfer_flags = -1;

/* SPI Transfer Flags */
static int hf_greybus_spi_xfer_read = -1;
static int hf_greybus_spi_xfer_write = -1;
static int hf_greybus_spi_xfer_inprogress = -1;
static const int *hf_greybus_spi_xfer_bits[] = {
	&hf_greybus_spi_xfer_read,
	&hf_greybus_spi_xfer_write,
	&hf_greybus_spi_xfer_inprogress,
	NULL,
};

/* SPI Mode Bits */
static int hf_greybus_spi_config_mode_cpha = -1;
static int hf_greybus_spi_config_mode_cpol = -1;
static int hf_greybus_spi_config_mode_cs_high = -1;
static int hf_greybus_spi_config_mode_lsb_first = -1;
static int hf_greybus_spi_config_mode_3wire = -1;
static int hf_greybus_spi_config_mode_loop = -1;
static int hf_greybus_spi_config_mode_no_cs = -1;
static int hf_greybus_spi_config_mode_ready = -1;
static const int *hf_greybus_spi_config_mode_bits[] = {
	&hf_greybus_spi_config_mode_cpha,
	&hf_greybus_spi_config_mode_cpol,
	&hf_greybus_spi_config_mode_cs_high,
	&hf_greybus_spi_config_mode_lsb_first,
	&hf_greybus_spi_config_mode_3wire,
	&hf_greybus_spi_config_mode_loop,
	&hf_greybus_spi_config_mode_no_cs,
	&hf_greybus_spi_config_mode_ready,
	NULL,
};

/* SPI Device Type Flags */
static int hf_greybus_spi_device_spi_dev = -1;
static int hf_greybus_spi_device_spi_nor = -1;
static int hf_greybus_spi_device_spi_modalias = -1;
static const int *hf_greybus_spi_device_bits[] = {
	&hf_greybus_spi_device_spi_dev,
	&hf_greybus_spi_device_spi_nor,
	&hf_greybus_spi_device_spi_modalias,
	NULL,
};

static gint ett_greybus = -1;
static dissector_handle_t greybus_handle;
static const true_false_string true_false = { "True", "False" };
static dissector_table_t greybus_dissector_table;

#define _decl(x) { GB_SPI_TYPE_ ## x, #x }
static const value_string packettypenames[] = {
	_decl(MASTER_CONFIG),
	_decl(DEVICE_CONFIG),
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
		&hf_greybus_spi_config_bpw_mask,
		{
			"Bits-per-Word Mask",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.bpw_mask",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_min_speed_hz,
		{
			"Minimum Bus Speed (Hz)",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.min_speed_hz",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_max_speed_hz,
		{
			"Maximum Bus Speed (Hz)",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.max_speed_hz",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode,
		{
			"Config Mode",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_flags,
		{
			"Config Flags",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.flags",
			FT_UINT16, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_num_chipselect,
		{
			"Number of Chip-Select Pins",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.num_chipselect",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_chip_select,
		{
			"Chip-Select",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.chip_select",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_bpw,
		{
			"Bits-per-Word",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.bpw",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_device_type,
		{
			"Device Type",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.device_type",
			FT_STRING, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_name,
		{
			"Name",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.name",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},

	/* SPI Config Mode */
	{
		&hf_greybus_spi_config_mode_cpha,
		{
			"Clock Phase (0: sample on first clock, 1: on second)",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.cpha",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_MODE_CPHA,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_cpol,
		{
			"Clock Polarity (0: clock low on idle, 1: high on idle)",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.cpol",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_MODE_CPOL,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_cs_high,
		{
			"Chip-Select Active High",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.cs_high",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_MODE_CS_HIGH,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_lsb_first,
		{
			"Least-significant Bit First",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.lsb_first",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_MODE_LSB_FIRST,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_3wire,
		{
			"SI/SO Signals Shared",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.3wire",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_MODE_3WIRE,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_loop,
		{
			"Loopback Mode",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.loop",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_MODE_LOOP,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_no_cs,
		{
			"One dev/bus No Chip-Select",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.no_cs",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_MODE_NO_CS,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_ready,
		{
			"Slave pulls low to pause",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.ready",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_MODE_READY,
			NULL, HFILL,
		},
	},

	/* SPI Config Flags */
	{
		&hf_greybus_spi_config_flag_half_duplex,
		{
			"Half Duplex",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.flag.half_duplex",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_FLAG_HALF_DUPLEX,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_flag_no_rx,
		{
			"No Receive",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.flag.no_rx",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_FLAG_NO_RX,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_flag_no_tx,
		{
			"No Transmit",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.flag.no_tx",
			FT_BOOLEAN, 16,
			NULL, GB_SPI_FLAG_NO_TX,
			NULL, HFILL,
		},
	},

	/* SPI Device Type */
	{
		&hf_greybus_spi_device_spi_dev,
		{
			"Generic Bit-Bang SPI Device",
			GREYBUS_PROTOCOL_FILTER_NAME ".device.bitbang",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_SPI_DEV,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_device_spi_nor,
		{
			"SPI NOR Device that supports JEDEC ID",
			GREYBUS_PROTOCOL_FILTER_NAME ".device.nor",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_SPI_NOR,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_device_spi_modalias,
		{
			"SPI Device Driver can be represented by name field",
			GREYBUS_PROTOCOL_FILTER_NAME ".device.modalias",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_SPI_MODALIAS,
			NULL, HFILL,
		},
	},

	/* SPI Transfer */
	{
		&hf_greybus_spi_transfer_chip_select,
		{
			"Chip-Select",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.chip_select",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_transfer_mode,
		{
			"Transfer Mode",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.mode",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_transfer_count,
		{
			"Number of Transfer Descriptors",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.count",
			FT_UINT8, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_transfer_speed_hz,
		{
			"Bus Speed (Hz)",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.speed_hz",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_transfer_len,
		{
			"Transfer Size (Bytes)",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.len",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_transfer_delay_usecs,
		{
			"Delay After Completion (microseconds)",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.delay_usecs",
			FT_UINT16, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_transfer_cs_change,
		{
			"Toggle Chip-Select After Completion",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.cs_change",
			FT_BOOLEAN, 8,
			TFS(&true_false), 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_transfer_bits_per_word,
		{
			"Bits-per-Word",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.bits_per_word",
			FT_UINT8, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_transfer_xfer_flags,
		{
			"Transfer Flags",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.xfer_flags",
			FT_UINT32, BASE_HEX,
			NULL, 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_transfer_data,
		{
			"Transfer Data",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.data",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL,
		},
	},

	/* Transfer Flags */
	{
		&hf_greybus_spi_xfer_read,
		{
			"Read",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.read",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_XFER_READ,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_xfer_write,
		{
			"Write",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.write",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_XFER_WRITE,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_xfer_inprogress,
		{
			"In Progress",
			GREYBUS_PROTOCOL_FILTER_NAME ".transfer.inprogress",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_XFER_INPROGRESS,
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
    case GB_SPI_TYPE_MASTER_CONFIG:
    	if (response) {
    		proto_tree_add_item(greybus_tree, hf_greybus_spi_config_bpw_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
    		proto_tree_add_item(greybus_tree, hf_greybus_spi_config_min_speed_hz, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
    		proto_tree_add_item(greybus_tree, hf_greybus_spi_config_max_speed_hz, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
			proto_tree_add_bitmask(greybus_tree, tvb, offset, hf_greybus_spi_config_mode, ett_greybus, hf_greybus_spi_config_mode_bits, ENC_LITTLE_ENDIAN);
            offset += 2;
			proto_tree_add_bitmask(greybus_tree, tvb, offset, hf_greybus_spi_config_flags, ett_greybus, hf_greybus_spi_config_flag_bits, ENC_LITTLE_ENDIAN);
            offset += 2;
    		proto_tree_add_item(greybus_tree, hf_greybus_spi_config_num_chipselect, tvb, offset, 1, ENC_NA);
            offset += 1;
    	}
    	break;
    case GB_SPI_TYPE_DEVICE_CONFIG:
    	if (response) {
			proto_tree_add_bitmask(greybus_tree, tvb, offset, hf_greybus_spi_config_mode, ett_greybus, hf_greybus_spi_config_mode_bits, ENC_LITTLE_ENDIAN);
            offset += 2;
    		proto_tree_add_item(greybus_tree, hf_greybus_spi_config_bpw, tvb, offset, 1, ENC_NA);
            offset += 1;
    		proto_tree_add_item(greybus_tree, hf_greybus_spi_config_max_speed_hz, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
			proto_tree_add_bitmask(greybus_tree, tvb, offset, hf_greybus_spi_config_device_type, ett_greybus, hf_greybus_spi_device_bits, ENC_NA);
            offset += 1;
    		proto_tree_add_item(greybus_tree, hf_greybus_spi_config_name, tvb, offset, 32, ENC_NA);
            offset += 32;
    	} else {
    		proto_tree_add_item(greybus_tree, hf_greybus_spi_config_chip_select, tvb, offset, 1, ENC_NA);
            offset += 1;
    	}
    	break;
    case GB_SPI_TYPE_TRANSFER:
		remaining = tvb_captured_length(tvb) - offset;
		proto_tree_add_item(greybus_tree, hf_greybus_spi_transfer_data, tvb, offset, remaining, ENC_NA);
		offset += remaining;
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

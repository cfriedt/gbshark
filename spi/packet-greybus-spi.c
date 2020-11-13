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

#include "greybus/greybus_types.h"
#include "greybus/greybus_protocols.h"

#include "packet-greybus-common.h"
#include "packet-greybus-spi.h"

#define GREYBUS_PROTOCOL_SHORT_NAME "Greybus SPI"
#define GREYBUS_PROTOCOL_NAME GREYBUS_PROTOCOL_SHORT_NAME " Protocol"
#define GREYBUS_PROTOCOL_FILTER_NAME "greybus.spi"

void proto_register_greybus(void);
void proto_reg_handoff_greybus(void);

static gpointer greybus_value(packet_info *pinfo);
static void greybus_prompt(packet_info *pinfo, gchar* result);

static int proto_greybus = -1;

static int hf_greybus_type = -1;

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
static gint ett_greybus = -1;
static dissector_handle_t greybus_handle;
static dissector_table_t greybus_dissector_table;

#define _decl(x) { GB_SPI_TYPE_ ## x, #x }
static const value_string packettypenames[] = {
	{ GB_REQUEST_TYPE_CPORT_SHUTDOWN, "CPORT_SHUTDOWN" },
	_decl(MASTER_CONFIG),
	_decl(DEVICE_CONFIG),
	_decl(TRANSFER),
	{ 0, NULL },
};
#undef _decl

#define _decl(x) { GB_SPI_SPI_ ## x, #x }
static const value_string devicetypenames[] = {
	_decl(DEV),
	_decl(NOR),
	_decl(MODALIAS),
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
			FT_UINT8, BASE_HEX,
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
			GREYBUS_PROTOCOL_FILTER_NAME ".config.device.type",
			FT_UINT8, BASE_DEC,
			VALS(devicetypenames), 0x0,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_name,
		{
			"Name",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.device.name",
			FT_STRING, BASE_NONE,
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
			FT_BOOLEAN, 8,
			NULL, GB_SPI_MODE_CPHA,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_cpol,
		{
			"Clock Polarity (0: clock low on idle, 1: high on idle)",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.cpol",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_MODE_CPOL,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_cs_high,
		{
			"Chip-Select Active High",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.cs_high",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_MODE_CS_HIGH,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_lsb_first,
		{
			"Least-significant Bit First",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.lsb_first",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_MODE_LSB_FIRST,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_3wire,
		{
			"SI/SO Signals Shared",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.3wire",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_MODE_3WIRE,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_loop,
		{
			"Loopback Mode",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.loop",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_MODE_LOOP,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_no_cs,
		{
			"One dev/bus No Chip-Select",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.no_cs",
			FT_BOOLEAN, 8,
			NULL, GB_SPI_MODE_NO_CS,
			NULL, HFILL,
		},
	},
	{
		&hf_greybus_spi_config_mode_ready,
		{
			"Slave pulls low to pause",
			GREYBUS_PROTOCOL_FILTER_NAME ".config.mode.ready",
			FT_BOOLEAN, 8,
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
			FT_UINT8, BASE_DEC,
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
			FT_UINT8, BASE_HEX,
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

static void greybus_dissect_master_config(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void) pinfo;
	if (gb_op_is_response(header)) {
		struct gb_spi_master_config_response response;
		response.bits_per_word_mask = tvb_get_letohl(tvb, offset);
		response.min_speed_hz = tvb_get_letohl(tvb, offset + 4);
		response.max_speed_hz = tvb_get_letohl(tvb, offset + 8);
		response.mode = tvb_get_guint8(tvb, offset + 12);
		uint8_t pad = tvb_get_guint8(tvb, offset + 13);
		response.flags = tvb_get_letohs(tvb, offset + 14);
		response.num_chipselect = tvb_get_guint8(tvb, offset + 16);
		proto_tree_add_uint(greybus_tree, hf_greybus_spi_config_bpw_mask, tvb, offset, 4, response.bits_per_word_mask);
		proto_tree_add_uint(greybus_tree, hf_greybus_spi_config_min_speed_hz, tvb, offset + 4, 4, response.min_speed_hz);
		proto_tree_add_item(greybus_tree, hf_greybus_spi_config_max_speed_hz, tvb, offset + 8, 4, response.max_speed_hz);
		proto_tree_add_bitmask(greybus_tree, tvb, offset + 12, hf_greybus_spi_config_mode, ett_greybus, hf_greybus_spi_config_mode_bits, response.mode & 0xff);
		proto_tree_add_bytes(greybus_tree, hf_greybus_pad, tvb, offset + 13, 1, &pad);
		proto_tree_add_bitmask(greybus_tree, tvb, offset + 14, hf_greybus_spi_config_flags, ett_greybus, hf_greybus_spi_config_flag_bits, response.flags);
		proto_tree_add_uint(greybus_tree, hf_greybus_spi_config_num_chipselect, tvb, offset + 16, 1, response.num_chipselect);
        offset += sizeof(response);
	}
}

static void greybus_dissect_device_config(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void) pinfo;
	if (gb_op_is_response(header)) {
		struct gb_spi_device_config_response response;
		/* gb_spi_device_config_response should really have a pad byte for after mode */
		response.mode = tvb_get_guint8(tvb, offset);
		uint8_t pad = tvb_get_guint8(tvb, offset + 1);
		response.bits_per_word = tvb_get_guint8(tvb, offset + 2);
		response.max_speed_hz = tvb_get_letohl(tvb, offset + 3);
		response.device_type = tvb_get_guint8(tvb, offset + 7);
		proto_tree_add_bitmask_value(greybus_tree, tvb, offset, hf_greybus_spi_config_mode, ett_greybus, hf_greybus_spi_config_mode_bits, response.mode & 0xff);
		proto_tree_add_bytes(greybus_tree, hf_greybus_pad, tvb, offset + 1, 1, &pad);
	    proto_tree_add_uint(greybus_tree, hf_greybus_spi_config_bpw, tvb, offset + 2, 1, response.bits_per_word);
	    proto_tree_add_uint(greybus_tree, hf_greybus_spi_config_max_speed_hz, tvb, offset + 3, 4, response.max_speed_hz);
        proto_tree_add_uint(greybus_tree, hf_greybus_spi_config_device_type, tvb, offset + 7, 1, response.device_type);
	    proto_tree_add_item(greybus_tree, hf_greybus_spi_config_name, tvb, offset + 8, sizeof(response.name), ENC_NA | ENC_ASCII);
        offset += sizeof(response);
	} else {
		proto_tree_add_item(greybus_tree, hf_greybus_spi_config_chip_select, tvb, offset, 1, ENC_NA);
        offset += 1;
	}
}

static void greybus_dissect_transfer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	guint offset = sizeof(*header);

	(void) pinfo;
	if (gb_op_is_response(header)) {
		uint16_t remaining = tvb_captured_length(tvb) - offset;
		proto_tree_add_item(greybus_tree, hf_greybus_spi_transfer_data, tvb, offset, remaining, ENC_NA);
		offset += remaining;
	} else {
		struct gb_spi_transfer_request req;
		req.chip_select = tvb_get_guint8(tvb, offset);
		req.mode = tvb_get_guint8(tvb, offset + 1);
		req.count = tvb_get_letohs(tvb, offset + 2);
		proto_tree_add_uint(greybus_tree, hf_greybus_spi_transfer_chip_select, tvb, offset, 1, req.chip_select);
		proto_tree_add_bitmask_value(greybus_tree, tvb, offset + 1, hf_greybus_spi_transfer_mode, ett_greybus, hf_greybus_spi_config_mode_bits, req.mode);
		proto_tree_add_uint(greybus_tree, hf_greybus_spi_transfer_count, tvb, offset + 2, 2, req.count);
		offset += sizeof(req);
		struct gb_spi_transfer xfer;
		size_t data_offset = offset + req.count * sizeof(xfer);
		for (size_t i = 0; i < req.count; ++i) {
			xfer.speed_hz = tvb_get_letohl(tvb, offset);
			xfer.len = tvb_get_letohl(tvb, offset + 4);
			xfer.delay_usecs = tvb_get_letohs(tvb, offset + 8);
			xfer.cs_change = tvb_get_guint8(tvb, offset + 10);
			xfer.bits_per_word = tvb_get_guint8(tvb, offset + 11);
			xfer.xfer_flags = tvb_get_guint8(tvb, offset + 12);
			proto_tree_add_uint(greybus_tree, hf_greybus_spi_transfer_speed_hz, tvb, offset, 4, xfer.speed_hz);
			proto_tree_add_uint(greybus_tree, hf_greybus_spi_transfer_len, tvb, offset + 4, 4, xfer.len);
			proto_tree_add_uint(greybus_tree, hf_greybus_spi_transfer_delay_usecs, tvb, offset + 8, 2, xfer.delay_usecs);
			proto_tree_add_boolean(greybus_tree, hf_greybus_spi_transfer_cs_change, tvb, offset + 10, 1, xfer.cs_change);
			proto_tree_add_uint(greybus_tree, hf_greybus_spi_transfer_bits_per_word, tvb, offset + 11, 1, xfer.bits_per_word);
			proto_tree_add_bitmask_value(greybus_tree, tvb, offset + 12, hf_greybus_spi_transfer_xfer_flags, ett_greybus, hf_greybus_spi_xfer_bits, xfer.xfer_flags);
			if (xfer.len > 0 && (xfer.xfer_flags & GB_SPI_XFER_WRITE) != 0) {
				proto_tree_add_item(greybus_tree, hf_greybus_spi_transfer_data, tvb, data_offset, xfer.len, ENC_NA);
				data_offset += xfer.len;
			}
			offset += sizeof(xfer);
		}
	}
}

static void greybus_dissect_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *greybus_tree, struct gb_operation_msg_hdr *header)
{
	switch(gb_op_get_type(header)) {
	case GB_REQUEST_TYPE_CPORT_SHUTDOWN:
		greybus_dissect_cport_shutdown(tvb, pinfo, ett_greybus, greybus_tree, header);
		break;
    case GB_SPI_TYPE_MASTER_CONFIG:
    	greybus_dissect_master_config(tvb, pinfo, greybus_tree, header);
    	break;
    case GB_SPI_TYPE_DEVICE_CONFIG:
    	greybus_dissect_device_config(tvb, pinfo, greybus_tree, header);
    	break;
    case GB_SPI_TYPE_TRANSFER:
    	greybus_dissect_transfer(tvb, pinfo, greybus_tree, header);
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
    proto_register_subtree_array(greybus_ett, array_length(greybus_ett));
    proto_register_field_array(proto_greybus, greybus_common_hf, greybus_common_hf_size);
    greybus_dissector_table = register_dissector_table(GREYBUS_PROTOCOL_FILTER_NAME ".type", GREYBUS_PROTOCOL_SHORT_NAME " Type", proto_greybus, FT_UINT8, BASE_HEX);
    register_decode_as(&greybus_da);
}

void proto_reg_handoff_greybus(void)
{
	dissector_add_for_decode_as("tcp.port", greybus_handle);
}

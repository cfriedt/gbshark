#ifndef PLUGINS_EPAN_GREYBUS_INCLUDE_PACKET_GREYBUS_COMMON_H_
#define PLUGINS_EPAN_GREYBUS_INCLUDE_PACKET_GREYBUS_COMMON_H_

#include <stdint.h>
#include <stdbool.h>

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

#define GB_OP_RESPONSE_MASK 0x80

extern hf_register_info greybus_common_hf[];
extern const size_t greybus_common_hf_size;
extern int hf_greybus_pad;
extern const true_false_string true_false;

static inline bool gb_op_is_response(const struct gb_operation_msg_hdr *header)
{
	return !!(header->type & GB_OP_RESPONSE_MASK);
}

static inline uint8_t gb_op_get_type(const struct gb_operation_msg_hdr *header)
{
	return header->type & ~GB_OP_RESPONSE_MASK;
}

guint greybus_dissect_header(tvbuff_t *tvb, packet_info *pinfo, int proto, int ett, proto_tree *tree, proto_tree **subtree, struct gb_operation_msg_hdr *header, const char *protocol_name, const value_string *packettypenames, int hf_greybus_type);
void greybus_dissect_cport_shutdown(tvbuff_t *tvb, packet_info *pinfo, int ett, proto_tree *tree, struct gb_operation_msg_hdr *header);

#endif /* PLUGINS_EPAN_GREYBUS_INCLUDE_PACKET_GREYBUS_COMMON_H_ */

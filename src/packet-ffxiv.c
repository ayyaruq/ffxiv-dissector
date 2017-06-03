#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

#include "src/packet-ffxiv.h"

#define FFXIV_COMPRESSED_FLAG 0x01
#define FFXIV_MAGIC 0x5252
#define FFXIV_PORT_RANGE "55000-55551"

static range_t *global_ffxiv_port_range = NULL;

// Assemble generic headers
static void build_frame_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, frame_header_t *eh_ptr) {
  eh_ptr->magic      = tvb_get_letohs(tvb, offset);
  eh_ptr->timestamp  = tvb_get_letoh64(tvb, offset + 16);
  eh_ptr->length     = tvb_get_letohl(tvb, offset + 24);
  eh_ptr->blocks     = tvb_get_letohs(tvb, offset + 30);
  eh_ptr->compressed = tvb_get_guint8(tvb, 33);

  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_magic, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_length, tvb, 24, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_count, tvb, 30, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_flag_compressed, tvb, 33, 1, ENC_LITTLE_ENDIAN);

  // Switch this to ENC_TIME_MSECS or similar ater:
  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_timestamp, tvb, 16, 8, ENC_LITTLE_ENDIAN);
}

static void build_message_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, block_header_t *eh_ptr) {
  eh_ptr->length      = tvb_get_letohl(tvb, offset);
  eh_ptr->send_id     = tvb_get_letohl(tvb, offset + 4);
  eh_ptr->recv_id     = tvb_get_letohl(tvb, offset + 8);
  eh_ptr->block_type  = tvb_get_letohl(tvb, offset + 16);
  eh_ptr->timestamp   = tvb_get_letoh64(tvb, offset + 24);

  proto_tree_add_item(tree, hf_ffxiv_message_pdu_length, tvb, 0, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_message_pdu_send_id, tvb, 4, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_message_pdu_recv_id, tvb, 8, 4, ENC_LITTLE_ENDIAN);

  // This is actually little endian, but we display it as BE to make debugging easier for now
  proto_tree_add_item(tree, hf_ffxiv_message_pdu_type, tvb, 16, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_message_pdu_timestamp, tvb, 24, 8, ENC_LITTLE_ENDIAN);
}

// Deal with multiple payloads in a single PDU
static guint32 get_frame_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data) {
  return tvb_get_letohl(tvb, offset + 24);
}

static guint32 get_message_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data) {
  return tvb_get_letohl(tvb, offset);
}

// Message header dissector
static int dissect_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  proto_tree      *message_tree = NULL;
  proto_item      *ti = NULL;
  block_header_t  header;
  int             datalen;
  int             orig_offset;
  int             offset = 0;
  int             reported_datalen;
  int             reported_length;
  tvbuff_t        *message_tvb;

  // Verify we have a full message in the tvb
  reported_length = tvb_reported_length_remaining(tvb, offset);
  if (reported_length < BLOCK_HEADER_LEN) {
    return -1;
  }

  // Set packet protocol column, emty info
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FFXIV");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_ffxiv, tvb, offset, -1, ENC_NA);
  message_tree = proto_item_add_subtree(ti, ett_ffxiv);

  orig_offset = offset;

  build_message_header(tvb, orig_offset, pinfo, message_tree, &header);
  if (reported_length < header.length) {
    return -1;
  }

  offset += BLOCK_HEADER_LEN;

  reported_datalen = tvb_reported_length_remaining(tvb, offset);
  datalen          = tvb_captured_length_remaining(tvb, offset);

  // TODO: fix this to deal with partial/malformed packets
  if (datalen > header.length) {
    // we probably have a partial block but eh
    datalen = (int)header.length;
  }

  if (reported_datalen > header.length) {
    // same
    reported_datalen = (int)header.length;
  }

  /*
    TODO: insert code for dealing with message types,
    for now register it as generic data.
  */

  message_tvb = tvb_new_subset_length(tvb, 0, header.length);

  add_new_data_source(pinfo, message_tvb, "Message Data");

  return tvb_captured_length(message_tvb);
}

// Frame header dissector
static int dissect_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  proto_tree          *frame_tree = NULL;
  proto_item          *ti = NULL;
  frame_header_t      header;
  int                 offset = 0;
  int                 length;
  int                 reported_datalen;
  tvbuff_t            *payload_tvb;
  tvbuff_t            *remaining_messages_tvb;

  // Verify we have a full frame header, if not we need reassembly
  reported_datalen = tvb_reported_length_remaining(tvb, offset);
  if (reported_datalen < FRAME_HEADER_LEN) {
    return -1;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FFXIV");
  col_clear(pinfo->cinfo, COL_INFO);

  ti         = proto_tree_add_item(tree, proto_ffxiv, tvb, 0, -1, ENC_NA);
  frame_tree = proto_item_add_subtree(ti, ett_ffxiv);

  build_frame_header(tvb, offset, pinfo, frame_tree, &header);

  if (header.compressed & FFXIV_COMPRESSED_FLAG) {
    payload_tvb = tvb_uncompress(tvb, FRAME_HEADER_LEN, tvb_reported_length_remaining(tvb, FRAME_HEADER_LEN));
  } else {
    payload_tvb = tvb_new_subset_remaining(tvb, FRAME_HEADER_LEN);
  }

  remaining_messages_tvb = payload_tvb;
  offset = 0;
  do {
    remaining_messages_tvb = tvb_new_subset_remaining(remaining_messages_tvb, offset);
    length = dissect_message(remaining_messages_tvb, pinfo, frame_tree, data);
    offset = length;
  } while (length >= BLOCK_HEADER_LEN);

  // TODO: if remaining_messages_tvb has length > 0 here it's most likely corrupted or spread over multiple frames

  return tvb_captured_length(payload_tvb);
}

// Main dissection method
static int dissect_ffxiv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  // Verify we have an actual frame header
  if (!tvb_bytes_exist(tvb, 0, FRAME_HEADER_LEN))
    return 0;

  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN, get_frame_length, dissect_frame, data);

  return tvb_captured_length(tvb);
}

// Wireshark standard is to stick these at the end
void proto_register_ffxiv(void) {
  static hf_register_info hf[] = {
    { &hf_ffxiv_frame_pdu_magic,
      { "Frame Magic", "ffxiv.frame.magic",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
    // Do something here to get timestamps rendered properly
    { &hf_ffxiv_frame_pdu_timestamp,
      { "Frame Timestamp", "ffxiv.frame.timestamp",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ffxiv_frame_pdu_length,
     { "Frame Length", "ffxiv.frame.length",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ffxiv_frame_pdu_count,
      { "Frame Count", "ffxiv.frame.count",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ffxiv_frame_flag_compressed,
      { "Frame Compression", "ffxiv.frame.compressed",
        FT_BOOLEAN, 8,
        NULL, FFXIV_COMPRESSED_FLAG,
        NULL, HFILL
      }
    },
    { &hf_ffxiv_message_pdu_length,
      { "Message Length", "ffxiv.message.length",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ffxiv_message_pdu_send_id,
      { "Message Sender ID", "ffxiv.message.sender",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ffxiv_message_pdu_recv_id,
      { "Message Receiver ID", "ffxiv.message.receiver",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ffxiv_message_pdu_type,
      { "Message Type", "ffxiv.message.type",
        FT_UINT32, BASE_HEX,
        NULL, 0x0,
        NULL, HFILL
      }
    },
    { &hf_ffxiv_message_pdu_timestamp,
      { "Message Timestamp", "ffxiv.message.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
        NULL, 0x0,
        "The timestamp of the message event", HFILL
      }
    },
  };

  static gint *ett[] = {
    &ett_ffxiv
  };

  module_t          *ffxiv_module;
  dissector_table_t ffxiv_frame_magic_table;

  proto_ffxiv = proto_register_protocol("FFXIV", "FFXIV", "ffxiv");
  proto_register_field_array(proto_ffxiv, hf, array_length(hf));

  proto_register_subtree_array(ett, array_length(ett));

  ffxiv_module = prefs_register_protocol(proto_ffxiv, NULL);

  ffxiv_frame_magic_table = register_dissector_table(
    "ffxiv.frame.magic", "FFXIV Magic Byte", proto_ffxiv, FT_UINT16, BASE_DEC
  );

  range_convert_str(&global_ffxiv_port_range, FFXIV_PORT_RANGE, 55551);
  prefs_register_range_preference(ffxiv_module, "tcp.port", "FFXIV port range",
    "Range of ports to look for FFXIV traffic on.", &global_ffxiv_port_range, 55551
  );
}

// Setup ranged port handlers
static void ffxiv_tcp_dissector_add(guint32 port) {
  dissector_add_uint("tcp.port", port, ffxiv_handle);
}

static void ffxiv_tcp_dissector_delete(guint32 port) {
  dissector_delete_uint("tcp.port", port, ffxiv_handle);
}

// Register handlers
void proto_reg_handoff_ffxiv(void) {
  static range_t *ffxiv_port_range;
  static gboolean initialised = FALSE;

  if (!initialised) {
    ffxiv_handle = register_dissector("ffxiv", dissect_ffxiv, proto_ffxiv);
    initialised = TRUE;
  } else {
    range_foreach(ffxiv_port_range, ffxiv_tcp_dissector_delete);
    g_free(ffxiv_port_range);
  }

  ffxiv_port_range = range_copy(global_ffxiv_port_range);
  range_foreach(ffxiv_port_range, ffxiv_tcp_dissector_add);

  dissector_add_uint("ffxiv.frame.magic", FFXIV_MAGIC, ffxiv_handle);
}

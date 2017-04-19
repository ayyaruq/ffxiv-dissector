#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

#include "src/packet-ffxiv.h"

#define FFXIV_COMPRESSED_FLAG 0x01


// Assemble generic headers
static void build_frame_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, frame_header_t *eh_ptr) {
  eh_ptr->type       = tvb_get_letohs(tvb, offset);
  eh_ptr->timestamp  = tvb_get_letoh64(tvb, offset+16);
  eh_ptr->length     = tvb_get_letohl(tvb, offset+24);
  eh_ptr->blocks     = tvb_get_letohs(tvb, offset+30);
  eh_ptr->compressed = tvb_get_guint8(tvb, 33);

  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_type, tvb, 0, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_length, tvb, 24, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_count, tvb, 30, 2, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_frame_flag_compressed, tvb, 33, 1, ENC_LITTLE_ENDIAN);

  // Switch this to ENC_TIME_MSECS or similar ater:
  proto_tree_add_item(tree, hf_ffxiv_frame_pdu_timestamp, tvb, 16, 8, ENC_LITTLE_ENDIAN);
}

static void build_message_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, block_header_t *eh_ptr) {
  eh_ptr->block_length = tvb_get_letohl(tvb, offset);
  eh_ptr->entity_id    = tvb_get_letoh64(tvb, offset+4);
  eh_ptr->block_type   = tvb_get_letohl(tvb, offset+16);

  proto_tree_add_item(tree, hf_ffxiv_message_pdu_length, tvb, 0, 4, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_message_pdu_id, tvb, 4, 8, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree, hf_ffxiv_message_pdu_type, tvb, 16, 4, ENC_LITTLE_ENDIAN);
}

// Deal with multiple payloads in a single PDU
static guint32 get_ffxiv_frame_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data) {
  return tvb_get_ntohl(tvb, offset+24);
}

static guint32 get_ffxiv_message_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data) {
  return tvb_get_ntohl(tvb, offset);
}

// Message dissection method
static int dissect_message(
  tvbuff_t *tvb, int offset,
  packet_info *pinfo,
  proto_tree *tree,
  const char* proto_tag, int proto,
  void *data
) {
  proto_tree          *message_tree = NULL;
  proto_item          *ti = NULL;
  block_header_t      header;
  int                 datalen;
  int                 orig_offset;
  int                 reported_datalen;
  int                 reported_length;
  tvbuff_t            *next_tvb;


  // Verify we have a full message in the tvb
  reported_length = tvb_reported_length_remaining(tvb, offset);
  if (reported_length < 32) {
    return -1;
  }

  // Set packet protocol column, emty info
  col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_tag);
  col_clear(pinfo->cinfo,COL_INFO);

  ti = proto_tree_add_item(tree, proto, tvb, offset, -1, ENC_NA);
  message_tree = proto_item_add_subtree(ti, ett_ffxiv_message);

  orig_offset = offset;

  build_message_header(tvb, orig_offset, pinfo, message_tree, &header);
  offset += BLOCK_HEADER_LEN;

  reported_datalen = tvb_reported_length_remaining(tvb, offset);
  datalen          = tvb_captured_length_remaining(tvb, offset);

  // TODO: fix this to deal with partial/malformed packets
  if (datalen > header.block_length) {
    // we probably have a partial block but eh
    datalen = (int)header.block_length;
  }

  if (reported_datalen > header.block_length) {
    // same
    reported_datalen = (int)header.block_length;
  }

  /*
    TODO: insert code for dealing with message types,
    for now register it as generic data.
  */

  return tvb_captured_length(tvb);
}

static int dissect_ffxiv_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {}

// Main dissection method
static int dissect_ffxiv_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  proto_tree          *frame_tree = NULL;
  proto_item          *ti = NULL;
  frame_header_t      header;
  int                 orig_offset;
  int                 offset = 0;
  int                 length;
  int                 captured_datalen;
  int                 reported_datalen;
  dissector_handle_t  next_handle = NULL;
  tvbuff_t            *next_tvb;

  // Verify we have a full frame header at least in the tvb
  reported_datalen = tvb_reported_length_remaining(tvb, offset);
  if (reported_datalen < 48) {
    return -1;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "FFXIV");
  col_clear(pinfo->cinfo,COL_INFO);

  ti         = proto_tree_add_item(tree, proto_ffxiv_frame, tvb, 0, -1, ENC_NA);
  frame_tree = proto_item_add_subtree(ti, ett_ffxiv_frame);

  orig_offset = offset;

  build_frame_header(tvb, orig_offset, pinfo, frame_tree, &header);
  offset += FRAME_HEADER_LEN;

  // This is wrong - maybe? We should only have a single frame here from the top level dissector
  if (header.compressed & FFXIV_COMPRESSED_FLAG) {
    next_tvb = tvb_uncompress(tvb, FRAME_HEADER_LEN, tvb_reported_length_remaining(tvb, FRAME_HEADER_LEN));
  } else {
    next_tvb = tvb_new_subset_remaining(tvb, FRAME_HEADER_LEN);
  }

  add_new_data_source(pinfo, next_tvb, "Message Data");

  tcp_dissect_pdus(next_tvb, pinfo, tree, TRUE, BLOCK_HEADER_LEN,
                   get_ffxiv_message_length, dissect_message, data);

  return tvb_captured_length(next_tvb);
}

static int dissect_ffxiv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  if (!tvb_bytes_exist(tvb, 0, FRAME_HEADER_LEN))
    return 0;

  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, FRAME_HEADER_LEN,
                   get_ffxiv_frame_length, dissect_ffxiv_frame, data);

  return tvb_captured_length(tvb);
}

// Wireshark standard is to stick these at the end
void proto_register_ffxiv(void) {
  static hf_register_info hf[] = {
    { &hf_ffxiv_message_pdu_length,
      { "Block Length", "ffxiv.message.length",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
     { &hf_ffxiv_message_pdu_id,
      { "Block Length", "ffxiv.message.id",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
     { &hf_ffxiv_message_pdu_type,
      { "Block Length", "ffxiv.message.type",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    }
  };

  static gint *ett[] = {
    &ett_ffxiv
  };

  module_t *ffxiv_module;

  proto_ffxiv = proto_register_protocol ("FFXIV", "FFXIV", "ffxiv");
  proto_register_field_array(proto_ffxiv, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ffxiv_handle = register_dissector("ffxiv", dissect_ffxiv, proto_ffxiv);
  ffxiv_module = prefs_register_protocol(proto_ffxiv, NULL);

  // prefs_register_range_preference(ffxiv_module, "port range", "FFXIV port range",
  //                                 "Range of ports to look for FFXIV traffic on.",
  //                                 &global_ffxiv_port_range, 55551);
}

void proto_register_ffxiv_frame(void) {
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_ffxiv_frame
  };

  proto_ffxiv_frame = proto_register_protocol (
    "FFXIV Frame",    /* name       */
    "FFXIV Frame",    /* short name */
    "ffxiv_frame"     /* abbrev     */
  );

  //proto_register_field_array(proto_ffxiv_frame, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void proto_register_ffxiv_message(void) {
  static gint *ett[] = {
    &ett_ffxiv_message
  };

  static hf_register_info hf[] = {
    { &hf_ffxiv_message_pdu_length,
      { "Block Length", "ffxiv.message.length",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
     { &hf_ffxiv_message_pdu_id,
      { "Block Length", "ffxiv.message.id",
        FT_UINT64, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    },
     { &hf_ffxiv_message_pdu_type,
      { "Block Length", "ffxiv.message.type",
        FT_UINT32, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL
      }
    }
  };

  proto_ffxiv_message = proto_register_protocol (
    "FFXIV Message",    /* name       */
    "FFXIV MSG",        /* short name */
    "ffxiv_msg"         /* abbrev     */
  );

  proto_register_subtree_array(ett, array_length(ett));
}

// Register handlers
void proto_reg_handoff_ffxiv(void) {
  ffxiv_frame_handle   = create_dissector_handle(dissect_ffxiv_frame, proto_ffxiv_frame);
  ffxiv_message_handle = create_dissector_handle(dissect_ffxiv_message, proto_ffxiv_message);

  // change to dissector_add_uint_with_preference when adding preference for port
  dissector_add_uint("tcp.port", 55023, ffxiv_handle);
}

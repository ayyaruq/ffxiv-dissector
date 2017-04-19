// General
#include <stdint.h>

#define FRAME_HEADER_LEN 40
#define BLOCK_HEADER_LEN 32

static dissector_handle_t ffxiv_handle;
static dissector_handle_t ffxiv_frame_handle;
static dissector_handle_t ffxiv_message_handle;

static int proto_ffxiv = -1;
static int proto_ffxiv_frame = -1;
static int proto_ffxiv_message = -1;

static gint ett_ffxiv = -1;
static gint ett_ffxiv_frame = -1;
static gint ett_ffxiv_message = -1;

// FFXIV protocol generic types
typedef struct {
  uint16_t  type;
  uint8_t   mystery1[16]; // unknown leading 16 bytes
  uint64_t  timestamp;
  uint32_t  length;
  uint8_t   mystery2[2];  // unknown bytes 29-30
  uint16_t  blocks;
  uint8_t   mystery3;     // unknown byte 32
  uint8_t   compressed;
  uint8_t   mystery4[6];  // unknown bytes 34-39
} frame_header_t;

/*
  So the block type could be uint16_t[14:15] in which case the mystery1 is
  uint16_t[12:13] and the subsequent mystery data resumes
  for some subset of uint128_t[16:31], ie:

  typedef struct {
    uint32_t  block_length;  // [0:3]
    uint64_t  entity_id;     // [4:11]
    uint16_t  mystery1;      // [12:13]
    uint16_t  block_type;    // [14:15]
    uint32_t  mystery2;      // [16:19]
    uint32_t  mystery3;      // [20:23]
    uint64_t  mystery4;      // [24:31]
  } block_header_t;
*/
typedef struct {
  uint32_t  block_length;  // [0:3]
  uint64_t  entity_id;     // [4:11]
  uint32_t  mystery1;      // [12:15]
  uint32_t  block_type;    // [16:20]
  uint32_t  mystery2;      // these could be smaller, no idea what's after header[20:]
  uint32_t  mystery3;
  uint32_t  mystery4;
} block_header_t;

// FFXIV Frame
static int hf_ffxiv_frame_pdu_type = -1;
static int hf_ffxiv_frame_pdu_timestamp = -1;
static int hf_ffxiv_frame_pdu_length = -1;
static int hf_ffxiv_frame_pdu_count = -1;
static int hf_ffxiv_frame_flag_compressed = -1;

// FFXIV Message
static int hf_ffxiv_message_pdu_length = -1;
static int hf_ffxiv_message_pdu_id = -1;
static int hf_ffxiv_message_pdu_type = -1;

// Utility methods
static guint32 get_ffxiv_frame_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data);
static guint32 get_ffxiv_message_length(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data);
static void build_frame_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, frame_header_t *eh_ptr);
static void build_message_header(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, block_header_t *eh_ptr);

// Dissection methods
static int dissect_ffxiv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_ffxiv_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_ffxiv_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
static int dissect_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, const char* proto_tag, int proto, void *data);

/* Feeds attacker-controlled bytes through stun_agent_validate() (every compatibility mode and
 * credential flavour) and then walks every attribute accessor on whatever message it accepted.
 *
 * Input: byte 0 selects the agent configuration, the rest is the datagram. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "stun/stunagent.h"
#include "stun/stunmessage.h"

static bool
validater (StunAgent *agent, StunMessage *message, uint8_t *username,
    uint16_t username_len, uint8_t **password, size_t *password_len,
    void *user_data)
{
  static uint8_t pwd[] = "VOkJxbRl1RmTxUk/WvJxBt";

  *password = pwd;
  *password_len = sizeof (pwd) - 1;
  return true;
}

static const StunAttribute attrs[] = {
  STUN_ATTRIBUTE_MAPPED_ADDRESS, STUN_ATTRIBUTE_USERNAME, STUN_ATTRIBUTE_ERROR_CODE,
  STUN_ATTRIBUTE_LIFETIME, STUN_ATTRIBUTE_BANDWIDTH, STUN_ATTRIBUTE_XOR_PEER_ADDRESS,
  STUN_ATTRIBUTE_DATA, STUN_ATTRIBUTE_REALM, STUN_ATTRIBUTE_NONCE,
  STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
  STUN_ATTRIBUTE_PRIORITY, STUN_ATTRIBUTE_USE_CANDIDATE, STUN_ATTRIBUTE_SOFTWARE,
  STUN_ATTRIBUTE_FINGERPRINT, STUN_ATTRIBUTE_ICE_CONTROLLED,
  STUN_ATTRIBUTE_ICE_CONTROLLING, STUN_ATTRIBUTE_RESERVATION_TOKEN,
  STUN_ATTRIBUTE_EVEN_PORT, STUN_ATTRIBUTE_REQUESTED_TRANSPORT,
  STUN_ATTRIBUTE_MS_VERSION, STUN_ATTRIBUTE_MS_XOR_MAPPED_ADDRESS,
  STUN_ATTRIBUTE_ALTERNATE_SERVER, STUN_ATTRIBUTE_UNKNOWN_ATTRIBUTES,
};

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  StunAgent agent;
  StunMessage msg;
  StunValidationStatus status;
  uint8_t cfg;
  uint8_t out[1500];
  uint8_t *buf;
  size_t i;

  if (size < 1)
    return -1;

  cfg = data[0];
  data++;
  size--;

  stun_agent_init (&agent, STUN_ALL_KNOWN_ATTRIBUTES,
      (StunCompatibility) (cfg & 3),
      ((cfg >> 2) & 1 ? STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS :
          STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS) |
      ((cfg >> 3) & 1 ? STUN_AGENT_USAGE_USE_FINGERPRINT : 0) |
      ((cfg >> 4) & 1 ? STUN_AGENT_USAGE_NO_INDICATION_AUTH : 0) |
      ((cfg >> 5) & 1 ? STUN_AGENT_USAGE_FORCE_VALIDATER : 0) |
      ((cfg >> 6) & 1 ? STUN_AGENT_USAGE_NO_ALIGNED_ATTRIBUTES : 0) |
      ((cfg >> 7) & 1 ? STUN_AGENT_USAGE_IGNORE_CREDENTIALS : 0));

  /* The agent keeps a pointer into the buffer, so give it a heap copy of exactly @size bytes. */
  buf = malloc (size ? size : 1);
  if (buf == NULL)
    return 0;
  memcpy (buf, data, size);

  status = stun_agent_validate (&agent, &msg, buf, size, validater, NULL);
  if (status == STUN_VALIDATION_NOT_STUN ||
      status == STUN_VALIDATION_INCOMPLETE_STUN) {
    free (buf);
    return -1;
  }

  stun_message_length (&msg);
  stun_message_has_cookie (&msg);
  {
    StunTransactionId id;
    stun_message_id (&msg, id);
  }

  for (i = 0; i < sizeof (attrs) / sizeof (attrs[0]); i++) {
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof (addr);
    char str[256];
    uint16_t len = 0;
    uint32_t v32;
    uint64_t v64;

    stun_message_has_attribute (&msg, attrs[i]);
    stun_message_find (&msg, attrs[i], &len);
    stun_message_find_flag (&msg, attrs[i]);
    stun_message_find32 (&msg, attrs[i], &v32);
    stun_message_find64 (&msg, attrs[i], &v64);
    stun_message_find_string (&msg, attrs[i], str, sizeof (str));
    stun_message_find_addr (&msg, attrs[i], &addr, &addrlen);
    addrlen = sizeof (addr);
    stun_message_find_xor_addr (&msg, attrs[i], &addr, &addrlen);
  }
  {
    int code;
    stun_message_find_error (&msg, &code);
  }

  /* Build the replies a server would send for this message. */
  {
    StunMessage reply;

    if (status == STUN_VALIDATION_UNKNOWN_REQUEST_ATTRIBUTE) {
      stun_agent_build_unknown_attributes_error (&agent, &reply, out,
          sizeof (out), &msg);
    } else if (status == STUN_VALIDATION_SUCCESS) {
      if (stun_agent_init_response (&agent, &reply, out, sizeof (out), &msg)) {
        stun_agent_finish_message (&agent, &reply,
            (const uint8_t *) "VOkJxbRl1RmTxUk/WvJxBt", 22);
      }
    } else if (status == STUN_VALIDATION_UNAUTHORIZED ||
        status == STUN_VALIDATION_BAD_REQUEST) {
      stun_agent_init_error (&agent, &reply, out, sizeof (out), &msg,
          status == STUN_VALIDATION_UNAUTHORIZED ? STUN_ERROR_UNAUTHORIZED :
          STUN_ERROR_BAD_REQUEST);
    }
  }

  free (buf);
  return 0;
}

/* Runs the STUN "usages" response processors (binding, ICE connectivity check, TURN allocate and
 * refresh) over a message accepted by stun_agent_validate().
 *
 * Input: byte 0 selects the agent compatibility, the rest is the datagram. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "stun/stunagent.h"
#include "stun/stunmessage.h"
#include "stun/usages/bind.h"
#include "stun/usages/ice.h"
#include "stun/usages/turn.h"

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

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  StunAgent agent;
  StunMessage msg;
  StunValidationStatus status;
  uint8_t cfg;
  uint8_t *buf;
  struct sockaddr_storage addr, alt, relay;
  socklen_t addrlen, altlen, relaylen;
  uint32_t bandwidth, lifetime;
  int c;

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
      STUN_AGENT_USAGE_IGNORE_CREDENTIALS);

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

  addrlen = altlen = sizeof (addr);
  stun_usage_bind_process (&msg, (struct sockaddr *) &addr, &addrlen,
      (struct sockaddr *) &alt, &altlen);

  for (c = STUN_USAGE_ICE_COMPATIBILITY_RFC5245;
       c <= STUN_USAGE_ICE_COMPATIBILITY_MSICE2; c++) {
    addrlen = sizeof (addr);
    stun_usage_ice_conncheck_process (&msg, &addr, &addrlen,
        (StunUsageIceCompatibility) c);
  }
  stun_usage_ice_conncheck_priority (&msg);
  stun_usage_ice_conncheck_use_candidate (&msg);

  for (c = STUN_USAGE_TURN_COMPATIBILITY_DRAFT9;
       c <= STUN_USAGE_TURN_COMPATIBILITY_RFC5766; c++) {
    addrlen = altlen = relaylen = sizeof (addr);
    stun_usage_turn_process (&msg, &relay, &relaylen, &addr, &addrlen, &alt,
        &altlen, &bandwidth, &lifetime, (StunUsageTurnCompatibility) c);
    stun_usage_turn_refresh_process (&msg, &lifetime,
        (StunUsageTurnCompatibility) c);
  }

  free (buf);
  return 0;
}

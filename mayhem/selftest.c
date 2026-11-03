/* Known-answer probes for the oracle: prints deterministic lines that mayhem/test.sh diffs against
 * golden values. Built dynamically with normal flags (an exit-code-only check would not notice a
 * library that silently returns nothing). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "stun/stunagent.h"
#include "stun/stunmessage.h"
#include "stun/stunhmac.h"
#include "agent/address.h"
#include "agent/agent.h"
#include "agent/candidate.h"
#include "agent/pseudotcp.h"

static void
hex (const char *name, const uint8_t *b, size_t n)
{
  size_t i;
  printf ("%s ", name);
  for (i = 0; i < n; i++)
    printf ("%02x", b[i]);
  printf ("\n");
}

static bool
validater (StunAgent *agent, StunMessage *message, uint8_t *username, uint16_t username_len,
    uint8_t **password, size_t *password_len, void *user_data)
{
  static uint8_t pwd[] = "VOkJxbRl1RmTxUk/WvJxBt";

  if (username_len != 9 || memcmp (username, "evtj:h6vY", 9) != 0)
    return false;
  *password = pwd;
  *password_len = sizeof pwd - 1;
  return true;
}

static void
kat_stun (void)
{
  static const uint8_t key[] = "VOkJxbRl1RmTxUk/WvJxBt";
  StunTransactionId id = { 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae };
  StunAgent agent;
  StunMessage msg, parsed;
  uint8_t buf[256];
  size_t len;
  const char *u;
  uint16_t ulen = 0;
  uint32_t prio = 0;
  uint8_t md5[16];
  StunValidationStatus st;

  stun_agent_init (&agent, STUN_ALL_KNOWN_ATTRIBUTES, STUN_COMPATIBILITY_RFC5389,
      STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS | STUN_AGENT_USAGE_USE_FINGERPRINT);
  msg.buffer = buf;
  msg.buffer_len = sizeof buf;
  msg.agent = &agent;
  msg.key = NULL;
  msg.key_len = 0;
  msg.long_term_valid = FALSE;
  stun_message_init (&msg, STUN_REQUEST, STUN_BINDING, id);
  stun_message_append_bytes (&msg, STUN_ATTRIBUTE_SOFTWARE, "STUN test client", 16);
  stun_message_append32 (&msg, STUN_ATTRIBUTE_PRIORITY, 0x6e0001ff);
  stun_message_append64 (&msg, STUN_ATTRIBUTE_ICE_CONTROLLED, 0x932ff9b151263b36ULL);
  stun_message_append_bytes (&msg, STUN_ATTRIBUTE_USERNAME, "evtj:h6vY", 9);
  len = stun_agent_finish_message (&agent, &msg, key, sizeof key - 1);
  printf ("stun-len %zu\n", len);
  hex ("stun-msg", buf, len);

  st = stun_agent_validate (&agent, &parsed, buf, len, validater, NULL);
  printf ("stun-validate %d class=%d method=%d\n", (int) st,
      (int) stun_message_get_class (&parsed), (int) stun_message_get_method (&parsed));
  buf[30] ^= 0x01;
  printf ("stun-validate-tampered %d\n",
      (int) stun_agent_validate (&agent, &parsed, buf, len, validater, NULL));
  buf[30] ^= 0x01;
  st = stun_agent_validate (&agent, &parsed, buf, len, validater, NULL);
  u = stun_message_find (&parsed, STUN_ATTRIBUTE_USERNAME, &ulen);
  printf ("stun-username %.*s\n", u ? (int) ulen : 0, u ? u : "");
  stun_message_find32 (&parsed, STUN_ATTRIBUTE_PRIORITY, &prio);
  printf ("stun-priority %u\n", prio);

  stun_hash_creds ((const uint8_t *) "realm", 5, (const uint8_t *) "user", 4,
      (const uint8_t *) "pass", 4, md5);
  hex ("stun-creds-md5", md5, 16);
}

static void
kat_address (void)
{
  NiceAddress a, b;
  char s[NICE_ADDRESS_STRING_LEN];

  nice_address_init (&a);
  printf ("addr-v4-ok %d\n", nice_address_set_from_string (&a, "192.0.2.10"));
  nice_address_set_port (&a, 3478);
  nice_address_to_string (&a, s);
  printf ("addr-v4 %s port=%u ipver=%d\n", s, nice_address_get_port (&a),
      nice_address_ip_version (&a));
  nice_address_init (&b);
  printf ("addr-v6-ok %d\n", nice_address_set_from_string (&b, "2001:db8:0:0:0:0:0:1"));
  nice_address_to_string (&b, s);
  printf ("addr-v6 %s ipver=%d private=%d\n", s, nice_address_ip_version (&b),
      nice_address_is_private (&b));
  nice_address_init (&b);
  printf ("addr-private %d\n",
      nice_address_set_from_string (&b, "10.1.2.3") && nice_address_is_private (&b));
  printf ("addr-bad %d\n", nice_address_set_from_string (&b, "not-an-address"));
  nice_address_init (&b);
  nice_address_set_from_string (&b, "192.0.2.10");
  nice_address_set_port (&b, 3478);
  printf ("addr-equal %d\n", nice_address_equal (&a, &b));
  nice_address_set_port (&b, 3479);
  printf ("addr-equal-port %d\n", nice_address_equal (&a, &b));
}

static void
kat_sdp (void)
{
  NiceAgent *agent = nice_agent_new (g_main_context_default (), NICE_COMPATIBILITY_RFC5245);
  NiceCandidate *c;
  char s[NICE_ADDRESS_STRING_LEN];
  gchar *out;

  nice_agent_add_stream (agent, 1);
  c = nice_agent_parse_remote_candidate_sdp (agent, 1,
      "a=candidate:1 1 UDP 2013266431 192.0.2.10 54609 typ srflx raddr 10.0.0.2 rport 4000");
  if (c == NULL) {
    printf ("sdp-cand NULL\n");
  } else {
    nice_address_to_string (&c->addr, s);
    printf ("sdp-cand %s %u type=%d transport=%d prio=%u comp=%u foundation=%s\n", s,
        nice_address_get_port (&c->addr), (int) c->type, (int) c->transport, c->priority,
        c->component_id, c->foundation);
    out = nice_agent_generate_local_candidate_sdp (agent, c);
    printf ("sdp-gen %s\n", out ? out : "NULL");
    g_free (out);
    nice_candidate_free (c);
  }
  g_object_unref (agent);
}

static GQueue q_to_left = G_QUEUE_INIT, q_to_right = G_QUEUE_INIT;
static PseudoTcpSocket *left, *right;
static GByteArray *received;
static GChecksum *sum;
static size_t sent_off;
#define PAYLOAD 40000

static PseudoTcpWriteResult
wr (PseudoTcpSocket *s, const gchar *buf, guint32 len, gpointer d)
{
  g_queue_push_tail (d, g_bytes_new (buf, len));
  return WR_SUCCESS;
}

static void
pump_send (void)
{
  guint8 chunk[1024];
  gint r;

  while (sent_off < PAYLOAD) {
    size_t n = PAYLOAD - sent_off < sizeof chunk ? PAYLOAD - sent_off : sizeof chunk, i;
    for (i = 0; i < n; i++)
      chunk[i] = (guint8) ((sent_off + i) * 7 + ((sent_off + i) >> 8));
    r = pseudo_tcp_socket_send (left, (const gchar *) chunk, n);
    if (r <= 0)
      break;
    sent_off += r;
  }
  if (sent_off >= PAYLOAD)
    pseudo_tcp_socket_close (left, FALSE);
}

static void l_writable (PseudoTcpSocket *s, gpointer d) { pump_send (); }
static void l_opened (PseudoTcpSocket *s, gpointer d) { pump_send (); }
static void noop (PseudoTcpSocket *s, gpointer d) {}
static void r_closed (PseudoTcpSocket *s, guint32 e, gpointer d) {}
static void
r_readable (PseudoTcpSocket *s, gpointer d)
{
  guint8 b[2048];
  gint n;
  while ((n = pseudo_tcp_socket_recv (s, (gchar *) b, sizeof b)) > 0) {
    g_checksum_update (sum, b, n);
    received->len += n;
  }
  if (n == 0 || received->len >= PAYLOAD)
    pseudo_tcp_socket_close (s, FALSE);
}

static void
kat_pseudotcp (void)
{
  PseudoTcpCallbacks lcb = { &q_to_right, l_opened, noop, l_writable, r_closed, wr };
  PseudoTcpCallbacks rcb = { &q_to_left, noop, r_readable, noop, r_closed, wr };
  gint64 end = g_get_monotonic_time () + 20 * G_USEC_PER_SEC;
  GBytes *b;

  received = g_byte_array_new ();
  sum = g_checksum_new (G_CHECKSUM_SHA1);
  left = pseudo_tcp_socket_new (7, &lcb);
  right = pseudo_tcp_socket_new (7, &rcb);
  pseudo_tcp_socket_notify_mtu (left, 1400);
  pseudo_tcp_socket_notify_mtu (right, 1400);
  pseudo_tcp_socket_connect (left);
  while (g_get_monotonic_time () < end &&
      !(received->len >= PAYLOAD &&
          pseudo_tcp_socket_get_available_bytes (right) <= 0 && g_queue_is_empty (&q_to_left))) {
    pseudo_tcp_socket_notify_clock (left);
    pseudo_tcp_socket_notify_clock (right);
    while ((b = g_queue_pop_head (&q_to_right))) {
      gsize n;
      const gchar *d = g_bytes_get_data (b, &n);
      pseudo_tcp_socket_notify_packet (right, d, n);
      g_bytes_unref (b);
    }
    while ((b = g_queue_pop_head (&q_to_left))) {
      gsize n;
      const gchar *d = g_bytes_get_data (b, &n);
      pseudo_tcp_socket_notify_packet (left, d, n);
      g_bytes_unref (b);
    }
    g_usleep (500);
  }
  printf ("pseudotcp-received %u\n", received->len);
  printf ("pseudotcp-sha1 %s\n", g_checksum_get_string (sum));
  g_checksum_free (sum);
  g_byte_array_free (received, TRUE);
  g_object_unref (left);
  g_object_unref (right);
}

int
main (void)
{
  kat_stun ();
  kat_address ();
  kat_sdp ();
  kat_pseudotcp ();
  return 0;
}

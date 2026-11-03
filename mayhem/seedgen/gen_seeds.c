/* One-off generator for the committed starter seeds (mayhem/<target>/testsuite/). Not part of the
 * build. Build and run it from /mayhem inside the commit image:
 *   clang -I. -Istun -Iagent -Isocket -Irandom -Inice -Ibuild/fuzz -Ibuild/fuzz/nice \
 *     $(pkg-config --cflags gio-2.0) mayhem/seedgen/gen_seeds.c build/fuzz/nice/libnice.a \
 *     $(pkg-config --libs gio-2.0 gthread-2.0 gnutls) -lm -o /tmp/gen_seeds
 *   /tmp/gen_seeds <outdir>          # writes <outdir>/{stun_message,stun_usages,pseudotcp,sdp}/... */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <glib.h>

#include "stun/stunagent.h"
#include "stun/stunmessage.h"
#include "stun/usages/bind.h"
#include "stun/usages/ice.h"
#include "stun/usages/turn.h"
#include "agent/pseudotcp.h"

static const char *outdir;
static const uint8_t PWD[] = "VOkJxbRl1RmTxUk/WvJxBt";

static void
emit (const char *target, const char *name, const uint8_t *prefix, size_t plen,
    const uint8_t *buf, size_t len)
{
  char dir[512], path[600];
  FILE *f;

  snprintf (dir, sizeof dir, "%s/%s", outdir, target);
  mkdir (dir, 0755);
  snprintf (path, sizeof path, "%s/%s", dir, name);
  f = fopen (path, "wb");
  fwrite (prefix, 1, plen, f);
  fwrite (buf, 1, len, f);
  fclose (f);
}

static void
emit_stun (const char *name, uint8_t cfg, const uint8_t *buf, size_t len)
{
  emit ("stun_message", name, &cfg, 1, buf, len);
  emit ("stun_usages", name, &cfg, 1, buf, len);
}

static void
fill_addr (struct sockaddr_storage *a, socklen_t *l, int v6)
{
  memset (a, 0, sizeof *a);
  if (v6) {
    struct sockaddr_in6 *s = (struct sockaddr_in6 *) a;
    s->sin6_family = AF_INET6;
    s->sin6_port = htons (5349);
    inet_pton (AF_INET6, "2001:db8::1234", &s->sin6_addr);
    *l = sizeof *s;
  } else {
    struct sockaddr_in *s = (struct sockaddr_in *) a;
    s->sin_family = AF_INET;
    s->sin_port = htons (3478);
    inet_pton (AF_INET, "192.0.2.33", &s->sin_addr);
    *l = sizeof *s;
  }
}

static void
stun_seeds (void)
{
  /* cfg byte: low 2 bits compat, bit2 long-term, bit3 fingerprint, bit5 force validater */
  struct { const char *tag; StunCompatibility compat; unsigned flags; uint8_t cfg; } agents[] = {
    { "rfc5389", STUN_COMPATIBILITY_RFC5389, STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS, 1 | 32 },
    { "rfc5389fp", STUN_COMPATIBILITY_RFC5389,
      STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS | STUN_AGENT_USAGE_USE_FINGERPRINT, 1 | 8 | 32 },
    { "rfc3489", STUN_COMPATIBILITY_RFC3489, STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS, 0 | 32 },
    { "msice2", STUN_COMPATIBILITY_MSICE2, STUN_AGENT_USAGE_SHORT_TERM_CREDENTIALS, 2 | 32 },
    { "oc2007", STUN_COMPATIBILITY_OC2007, STUN_AGENT_USAGE_LONG_TERM_CREDENTIALS, 3 | 4 | 32 },
  };
  size_t i;

  for (i = 0; i < G_N_ELEMENTS (agents); i++) {
    StunAgent agent, srv;
    StunMessage req, rsp, parsed;
    uint8_t buf[1500], rbuf[1500];
    size_t len;
    struct sockaddr_storage addr;
    socklen_t alen;
    char name[64];
    int v6;
    bool ctl = true;
    size_t elen = sizeof rbuf;

    stun_agent_init (&agent, STUN_ALL_KNOWN_ATTRIBUTES, agents[i].compat, agents[i].flags);
    stun_agent_init (&srv, STUN_ALL_KNOWN_ATTRIBUTES, agents[i].compat, agents[i].flags);

    /* plain binding request + success responses */
    len = stun_usage_bind_create (&agent, &req, buf, sizeof buf);
    snprintf (name, sizeof name, "bind_req_%s", agents[i].tag);
    emit_stun (name, agents[i].cfg, buf, len);
    stun_agent_validate (&srv, &parsed, buf, len, NULL, NULL);
    for (v6 = 0; v6 < 2; v6++) {
      fill_addr (&addr, &alen, v6);
      if (stun_agent_init_response (&srv, &rsp, rbuf, sizeof rbuf, &parsed)) {
        if (agents[i].compat == STUN_COMPATIBILITY_RFC3489)
          stun_message_append_addr (&rsp, STUN_ATTRIBUTE_MAPPED_ADDRESS,
              (struct sockaddr *) &addr, alen);
        else
          stun_message_append_xor_addr (&rsp, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &addr, alen);
        len = stun_agent_finish_message (&srv, &rsp, PWD, sizeof PWD - 1);
        snprintf (name, sizeof name, "bind_rsp%d_%s", v6 + 4, agents[i].tag);
        emit_stun (name, agents[i].cfg, rbuf, len);
      }
    }

    /* ICE connectivity check request + reply (needs a valid username) */
    len = stun_usage_ice_conncheck_create (&agent, &req, buf, sizeof buf,
        (const uint8_t *) "remote:local", 12, PWD, sizeof PWD - 1,
        true, true, 0x7e0000ff, 0x1122334455667788ULL, NULL,
        agents[i].compat == STUN_COMPATIBILITY_RFC5389 ? STUN_USAGE_ICE_COMPATIBILITY_RFC5245
        : agents[i].compat == STUN_COMPATIBILITY_RFC3489 ? STUN_USAGE_ICE_COMPATIBILITY_GOOGLE
        : STUN_USAGE_ICE_COMPATIBILITY_MSICE2);
    snprintf (name, sizeof name, "ice_req_%s", agents[i].tag);
    emit_stun (name, agents[i].cfg, buf, len);
    stun_agent_forget_transaction (&agent, ((StunTransactionId){0}));
    if (stun_agent_validate (&srv, &parsed, buf, len, NULL, NULL) != STUN_VALIDATION_NOT_STUN) {
      fill_addr (&addr, &alen, 0);
      elen = sizeof rbuf;
      if (stun_usage_ice_conncheck_create_reply (&srv, &parsed, &rsp, rbuf, &elen,
              &addr, alen, &ctl, 99,
              agents[i].compat == STUN_COMPATIBILITY_RFC5389 ? STUN_USAGE_ICE_COMPATIBILITY_RFC5245
              : STUN_USAGE_ICE_COMPATIBILITY_MSICE2) == STUN_USAGE_ICE_RETURN_SUCCESS ||
          elen > 0) {
        snprintf (name, sizeof name, "ice_rsp_%s", agents[i].tag);
        emit_stun (name, agents[i].cfg, rbuf, elen);
      }
    }

    /* TURN allocate request, success response, 401 challenge */
    len = stun_usage_turn_create (&agent, &req, buf, sizeof buf, NULL,
        STUN_USAGE_TURN_REQUEST_PORT_NORMAL, 0, 600,
        (uint8_t *) "user", 4, (uint8_t *) PWD, sizeof PWD - 1,
        agents[i].compat == STUN_COMPATIBILITY_RFC5389 ? STUN_USAGE_TURN_COMPATIBILITY_RFC5766
        : STUN_USAGE_TURN_COMPATIBILITY_OC2007);
    snprintf (name, sizeof name, "turn_req_%s", agents[i].tag);
    emit_stun (name, agents[i].cfg, buf, len);
    stun_agent_validate (&srv, &parsed, buf, len, NULL, NULL);
    for (v6 = 0; v6 < 2; v6++) {
      if (stun_agent_init_response (&srv, &rsp, rbuf, sizeof rbuf, &parsed)) {
        struct sockaddr_storage relay;
        socklen_t rl;
        fill_addr (&relay, &rl, v6);
        fill_addr (&addr, &alen, !v6);
        stun_message_append_xor_addr (&rsp, STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS, &relay, rl);
        stun_message_append_xor_addr (&rsp, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, &addr, alen);
        stun_message_append32 (&rsp, STUN_ATTRIBUTE_LIFETIME, 600);
        stun_message_append32 (&rsp, STUN_ATTRIBUTE_BANDWIDTH, 1000);
        len = stun_agent_finish_message (&srv, &rsp, PWD, sizeof PWD - 1);
        snprintf (name, sizeof name, "turn_rsp%d_%s", v6 + 4, agents[i].tag);
        emit_stun (name, agents[i].cfg, rbuf, len);
      }
    }
    if (stun_agent_init_error (&srv, &rsp, rbuf, sizeof rbuf, &parsed, STUN_ERROR_UNAUTHORIZED)) {
      stun_message_append_string (&rsp, STUN_ATTRIBUTE_REALM, "example.org");
      stun_message_append_bytes (&rsp, STUN_ATTRIBUTE_NONCE, "f//499k954d6OL34oL9FSTvy64sA", 28);
      len = stun_agent_finish_message (&srv, &rsp, NULL, 0);
      snprintf (name, sizeof name, "turn_401_%s", agents[i].tag);
      emit_stun (name, agents[i].cfg, rbuf, len);
    }
    if (stun_agent_init_error (&srv, &rsp, rbuf, sizeof rbuf, &parsed, STUN_ERROR_ALLOCATION_MISMATCH)) {
      len = stun_agent_finish_message (&srv, &rsp, NULL, 0);
      snprintf (name, sizeof name, "turn_437_%s", agents[i].tag);
      emit_stun (name, agents[i].cfg, rbuf, len);
    }
    if (stun_agent_init_error (&srv, &rsp, rbuf, sizeof rbuf, &parsed, STUN_ERROR_ROLE_CONFLICT)) {
      len = stun_agent_finish_message (&srv, &rsp, NULL, 0);
      snprintf (name, sizeof name, "err_487_%s", agents[i].tag);
      emit_stun (name, agents[i].cfg, rbuf, len);
    }
  }
}

/* ---- pseudotcp: record both directions of a loopback session ---- */
struct rec { PseudoTcpSocket *peer; GByteArray *out; GByteArray *other; int sent; int active; };
static struct rec L, R;
static PseudoTcpSocket *left, *right;
static GQueue to_left = G_QUEUE_INIT, to_right = G_QUEUE_INIT;

static void
drain (void)
{
  GBytes *b;
  int guard = 0;
  gboolean more = TRUE;

  while (more && guard++ < 1000) {
    more = FALSE;
    if ((b = g_queue_pop_head (&to_right))) {
      gsize n;
      const gchar *d = g_bytes_get_data (b, &n);
      pseudo_tcp_socket_notify_packet (right, d, n);
      g_bytes_unref (b);
      more = TRUE;
    }
    if ((b = g_queue_pop_head (&to_left))) {
      gsize n;
      const gchar *d = g_bytes_get_data (b, &n);
      pseudo_tcp_socket_notify_packet (left, d, n);
      g_bytes_unref (b);
      more = TRUE;
    }
  }
}

static void rec_frame (GByteArray *a, const gchar *b, guint32 len)
{
  guint8 h[2] = { len >> 8, len & 0xff };
  g_byte_array_append (a, h, 2);
  g_byte_array_append (a, (const guint8 *) b, len);
}

static PseudoTcpWriteResult
wr (PseudoTcpSocket *s, const gchar *buf, guint32 len, gpointer d)
{
  struct rec *r = d;
  rec_frame (r->out, buf, len);
  g_queue_push_tail (r == &L ? &to_right : &to_left, g_bytes_new (buf, len));
  return WR_SUCCESS;
}
static void opened (PseudoTcpSocket *s, gpointer d)
{
  struct rec *r = d;
  if (r == &L && !r->sent) {
    r->sent = 1;
    pseudo_tcp_socket_send (s, "abcdefghijklmnopqrstuvwxyz0123456789", 36);
    pseudo_tcp_socket_close (s, FALSE);
  }
}
static void readable (PseudoTcpSocket *s, gpointer d)
{
  char b[256];
  while (pseudo_tcp_socket_recv (s, b, sizeof b) > 0) ;
  pseudo_tcp_socket_close (s, FALSE);
}
static void writable (PseudoTcpSocket *s, gpointer d) {}
static void closed (PseudoTcpSocket *s, guint32 e, gpointer d) {}

static void
pseudotcp_seeds (void)
{
  PseudoTcpCallbacks lcb = { &L, opened, readable, writable, closed, wr };
  PseudoTcpCallbacks rcb = { &R, opened, readable, writable, closed, wr };
  int i;
  int variant;

  for (variant = 0; variant < 2; variant++) {
    L.out = g_byte_array_new ();
    R.out = g_byte_array_new ();
    L.sent = R.sent = 0;
    left = g_object_new (PSEUDO_TCP_SOCKET_TYPE, "conversation", 0x01020304, "callbacks", &lcb,
        "support-fin-ack", (gboolean) variant, NULL);
    right = g_object_new (PSEUDO_TCP_SOCKET_TYPE, "conversation", 0x01020304, "callbacks", &rcb,
        "support-fin-ack", (gboolean) variant, NULL);
    pseudo_tcp_socket_notify_mtu (left, 1400);
    pseudo_tcp_socket_notify_mtu (right, 1400);
    pseudo_tcp_socket_connect (left);
    drain ();
    for (i = 0; i < 40; i++) {
      pseudo_tcp_socket_notify_clock (left);
      pseudo_tcp_socket_notify_clock (right);
      drain ();
      g_usleep (2000);
    }
    {
      /* passive side (flags 0|8 [|32]): packets the left socket sent */
      guint8 flags = 8 | (variant ? 32 : 0);
      char name[32];
      GByteArray *a = g_byte_array_new ();
      g_byte_array_append (a, &flags, 1);
      g_byte_array_append (a, L.out->data, L.out->len);
      snprintf (name, sizeof name, "passive_%d", variant);
      emit ("pseudotcp", name, NULL, 0, a->data, a->len);

      /* active side (connect=1, send=4): packets the right socket sent */
      flags = 1 | 4 | 8 | (variant ? 32 : 0);
      g_byte_array_set_size (a, 0);
      g_byte_array_append (a, &flags, 1);
      g_byte_array_append (a, R.out->data, R.out->len);
      snprintf (name, sizeof name, "active_%d", variant);
      emit ("pseudotcp", name, NULL, 0, a->data, a->len);
    }
    g_object_unref (left);
    g_object_unref (right);
  }
}

static void
sdp_seeds (void)
{
  static const char *sdps[] = {
    "m=audio 54609 ICE/SDP\na=ice-ufrag:AbCd\na=ice-pwd:0123456789abcdefghijkl\n"
    "a=candidate:1 1 UDP 2013266431 192.0.2.10 54609 typ host\n"
    "a=candidate:2 1 UDP 1677722111 203.0.113.7 61000 typ srflx raddr 192.0.2.10 rport 54609\n"
    "a=candidate:3 2 UDP 2013266430 192.0.2.10 54610 typ host\n",
    "m=video 9 ICE/SDP\na=ice-ufrag:Zy\na=ice-pwd:pwdpwdpwdpwdpwdpwdpwdpwd\n"
    "a=candidate:4 1 TCP 1518280447 2001:db8::5 9 typ host tcptype active\n"
    "a=candidate:5 1 UDP 100 198.51.100.4 3478 typ relay raddr 203.0.113.7 rport 61000\n"
    "a=candidate:6 1 UDP 90 198.51.100.4 3479 typ prflx\n",
  };
  static const char *cands[] = {
    "a=candidate:1 1 UDP 2013266431 192.0.2.10 54609 typ host",
    "a=candidate:Hx7a 2 UDP 1677722111 203.0.113.7 61000 typ srflx raddr 192.0.2.10 rport 54609",
    "a=candidate:9 1 TCP 1518280447 2001:db8::5 9 typ host tcptype passive",
  };
  static const char *addrs[] = { "192.0.2.10", "2001:db8::1", "::ffff:192.0.2.1", "fe80::1%eth0" };
  size_t i;
  char name[32];

  for (i = 0; i < G_N_ELEMENTS (sdps); i++) {
    snprintf (name, sizeof name, "sdp_%zu", i);
    emit ("sdp", name, (const uint8_t *) "\x00", 1, (const uint8_t *) sdps[i], strlen (sdps[i]));
    snprintf (name, sizeof name, "stream_%zu", i);
    emit ("sdp", name, (const uint8_t *) "\x01", 1, (const uint8_t *) sdps[i], strlen (sdps[i]));
  }
  for (i = 0; i < G_N_ELEMENTS (cands); i++) {
    snprintf (name, sizeof name, "cand_%zu", i);
    emit ("sdp", name, (const uint8_t *) "\x02", 1, (const uint8_t *) cands[i], strlen (cands[i]));
  }
  for (i = 0; i < G_N_ELEMENTS (addrs); i++) {
    snprintf (name, sizeof name, "addr_%zu", i);
    emit ("sdp", name, (const uint8_t *) "\x03", 1, (const uint8_t *) addrs[i], strlen (addrs[i]));
  }
}

int
main (int argc, char **argv)
{
  if (argc != 2)
    return 2;
  outdir = argv[1];
  stun_seeds ();
  pseudotcp_seeds ();
  sdp_seeds ();
  return 0;
}

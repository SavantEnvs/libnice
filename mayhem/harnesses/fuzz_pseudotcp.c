/* Drives one PseudoTcpSocket with a fuzzer-chosen stream of received packets.
 *
 * Input layout:
 *   byte 0      flags: bit0 connect() actively, bit1 enable nodelay, bit2 send data from the
 *               opened/writable callbacks, bit3 close at the end, bit4 shutdown(RD) midway,
 *               bit5 negotiate FIN-ACK
 *   then        frames of [u16 big-endian length][packet bytes]
 * The socket's conversation id is taken from the first four bytes of the first packet (its own
 * header), so real handshakes are accepted instead of being reset for a conversation mismatch. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "agent/pseudotcp.h"

struct ctx {
  unsigned flags;
  int sent_data;
};

static void
quiet_log (const gchar *domain, GLogLevelFlags level, const gchar *msg,
    gpointer data)
{
}

static void
opened (PseudoTcpSocket *sock, gpointer data)
{
  struct ctx *c = data;

  if ((c->flags & 4) && !c->sent_data) {
    c->sent_data = 1;
    pseudo_tcp_socket_send (sock, "abcdefghijklmnopqrstuvwxyz", 26);
  }
}

static void
readable (PseudoTcpSocket *sock, gpointer data)
{
  gchar buf[2048];
  gint len;

  do {
    len = pseudo_tcp_socket_recv (sock, buf, sizeof (buf));
  } while (len > 0);
}

static void
writable (PseudoTcpSocket *sock, gpointer data)
{
  opened (sock, data);
}

static void
closed (PseudoTcpSocket *sock, guint32 error, gpointer data)
{
}

static PseudoTcpWriteResult
write_packet (PseudoTcpSocket *sock, const gchar *buffer, guint32 len,
    gpointer data)
{
  return WR_SUCCESS;
}

int
LLVMFuzzerInitialize (int *argc, char ***argv)
{
  g_log_set_default_handler (quiet_log, NULL);
  return 0;
}

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  struct ctx c = { 0, 0 };
  PseudoTcpCallbacks cb = { &c, opened, readable, writable, closed,
    write_packet };
  PseudoTcpSocket *sock;
  uint32_t conv;
  size_t pos;
  int npackets = 0;
  uint8_t *pkt;

  if (size < 1 + 2 + 4)
    return -1;

  c.flags = data[0];
  pos = 1;
  conv = ((uint32_t) data[pos + 2] << 24) | ((uint32_t) data[pos + 3] << 16) |
      ((uint32_t) data[pos + 4] << 8) | data[pos + 5];

  sock = g_object_new (PSEUDO_TCP_SOCKET_TYPE, "conversation", conv, "callbacks", &cb,
      "support-fin-ack", (gboolean) ((c.flags & 32) != 0), NULL);
  if (sock == NULL)
    return 0;

  if (c.flags & 2)
    g_object_set (sock, "no-delay", TRUE, NULL);
  if (c.flags & 1)
    pseudo_tcp_socket_connect (sock);

  while (pos + 2 <= size) {
    size_t len = ((size_t) data[pos] << 8) | data[pos + 1];

    pos += 2;
    if (len > size - pos)
      len = size - pos;

    /* the agent hands over a malloc'd (aligned, exactly sized) datagram buffer */
    pkt = malloc (len ? len : 1);
    memcpy (pkt, data + pos, len);
    pseudo_tcp_socket_notify_packet (sock, (const gchar *) pkt, len);
    free (pkt);
    pseudo_tcp_socket_notify_clock (sock);
    pos += len;
    npackets++;

    if ((c.flags & 16) && npackets == 3)
      pseudo_tcp_socket_shutdown (sock, PSEUDO_TCP_SHUTDOWN_RD);
  }

  if (c.flags & 8)
    pseudo_tcp_socket_close (sock, FALSE);
  pseudo_tcp_socket_notify_clock (sock);

  g_object_unref (sock);
  return 0;
}

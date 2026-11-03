/* Feeds attacker-controlled SDP text to libnice's SDP parsers on a fresh agent.
 *
 * Input: byte 0 selects the entry point (0: whole SDP, 1: one stream's SDP, 2: one candidate line,
 * 3: address string), the rest is the text. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include "agent.h"
#include "address.h"

static void
quiet_log (const gchar *domain, GLogLevelFlags level, const gchar *msg,
    gpointer data)
{
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
  NiceAgent *agent;
  guint stream_id;
  gchar *text;
  uint8_t mode;

  if (size < 1)
    return -1;

  mode = data[0] & 3;
  text = g_strndup ((const gchar *) data + 1, size - 1);

  if (mode == 3) {
    NiceAddress addr;

    if (nice_address_set_from_string (&addr, text)) {
      gchar buf[NICE_ADDRESS_STRING_LEN];

      nice_address_to_string (&addr, buf);
      nice_address_get_port (&addr);
      nice_address_is_private (&addr);
      nice_address_is_valid (&addr);
    }
    g_free (text);
    return 0;
  }

  agent = nice_agent_new (g_main_context_default (), NICE_COMPATIBILITY_RFC5245);
  stream_id = nice_agent_add_stream (agent, 2);

  if (mode == 0) {
    gchar *local;

    nice_agent_parse_remote_sdp (agent, text);
    local = nice_agent_generate_local_sdp (agent);
    g_free (local);
  } else if (mode == 1) {
    gchar *ufrag = NULL, *pwd = NULL;
    GSList *cands = nice_agent_parse_remote_stream_sdp (agent, stream_id, text,
        &ufrag, &pwd);

    g_slist_free_full (cands, (GDestroyNotify) nice_candidate_free);
    g_free (ufrag);
    g_free (pwd);
  } else {
    NiceCandidate *cand = nice_agent_parse_remote_candidate_sdp (agent,
        stream_id, text);

    if (cand != NULL) {
      gchar *line = nice_agent_generate_local_candidate_sdp (agent, cand);

      g_free (line);
      nice_candidate_free (cand);
    }
  }

  g_object_unref (agent);
  g_free (text);
  return 0;
}

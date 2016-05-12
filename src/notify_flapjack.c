/**
 * collectd - src/notify_flapjack.c
 * Copyright (C) 2016       Birger Schmidt
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Birger Schmidt <bs-collectd-flapjack at netgaroo.com>
 */

#include "collectd.h"
#include "plugin.h"
#include "common.h"
#include "configfile.h"

#include <pthread.h>
#include <hiredis/hiredis.h>

#define NAGIOS_OK       0
#define NAGIOS_WARNING  1
#define NAGIOS_CRITICAL 2
#define NAGIOS_UNKNOWN  3

char servicestate[][10] = { "OK", "WARNING", "CRITICAL", "UNKNOWN", };

struct fj_node_s
{
  char name[DATA_MAX_NAME_LEN];

  char *host;
  int port;
  struct timeval timeout;
  int database;
  int flapjack_version;

  redisContext *conn;
  pthread_mutex_t lock;
};
typedef struct fj_node_s fj_node_t;

/*
 * Functions
 */

/* Counts escape sequences within a string

   Used for calculating the size of the destination string for
   expand_escapes, below.
*/
int count_escapes(const char *src) {
    int e = 0;

    char c = *(src++);

    while (c) {
        switch(c) {
            case '\\':
                e++;
                break;
            case '\"':
                e++;
                break;
        }
        c = *(src++);
    }

    return(e);
}

/* Expands escape sequences within a string
 *
 * src must be a string with a NUL terminator
 *
 * NUL characters are not expanded to \0 (otherwise how would we know when
 * the input string ends?)
 *
 * Adapted from http://stackoverflow.com/questions/3535023/convert-characters-in-a-c-string-to-their-escape-sequences
 */
char *expand_escapes(const char* src)
{
    char* dest;
    char* d;

    if ((src == NULL) || ( strlen(src) == 0)) {
        dest = malloc(sizeof(char));
        d = dest;
    } else {
        // escaped lengths must take NUL terminator into account
        int dest_len = strlen(src) + count_escapes(src) + 1;
        dest = malloc(dest_len * sizeof(char));
        d = dest;

        char c = *(src++);

        while (c) {
            switch(c) {
                case '\\':
                    *(d++) = '\\';
                    *(d++) = '\\';
                    break;
                case '\"':
                    *(d++) = '\\';
                    *(d++) = '\"';
                    break;
                default:
                    *(d++) = c;
            }
            c = *(src++);
        }
    }

    *d = '\0'; /* Ensure NUL terminator */

    return(dest);
}

int generate_event(char *buffer, size_t buffer_size, const char *host_name, char *service_name,
                   char *state, const char *output, char *long_output, char *tags,
                   long initial_failure_delay, long repeat_failure_delay,
                   long initial_recovery_delay, double event_time) {

    char *escaped_host_name    = expand_escapes(host_name);
    char *escaped_service_name = expand_escapes(service_name);
    char *escaped_state        = expand_escapes(state);
    char *escaped_output       = expand_escapes(output);
    char *escaped_long_output  = expand_escapes(long_output);

    int written = snprintf(buffer, buffer_size,
                            "{"
                                "\"entity\":\"%s\","                   // HOSTNAME
                                "\"check\":\"%s\","                    // SERVICENAME
                                "\"type\":\"service\","                // type
                                "\"state\":\"%s\","                    // HOSTSTATE
                                "\"summary\":\"%s\","                  // HOSTOUTPUT
                                "\"details\":\"%s\","                  // HOSTlongoutput
                                "\"tags\":[%s],"                       // tags
                                "\"initial_failure_delay\":%lu,"       // initial_failure_delay
                                "\"repeat_failure_delay\":%lu,"        // repeat_failure_delay
                                //"\"initial_recovery_delay\":%lu,"      // initial_recovery_delay
                                "\"time\":%.0f"                        // TIMET
                            "}",
                                escaped_host_name,
                                escaped_service_name,
                                escaped_state,
                                escaped_output,
                                escaped_long_output,
                                tags,
                                initial_failure_delay,
                                repeat_failure_delay,
                                //initial_recovery_delay,
                                event_time);

    sfree(escaped_host_name);
    sfree(escaped_service_name);
    sfree(escaped_state);
    sfree(escaped_output);
    sfree(escaped_long_output);

    return(written);
}

static void fj_config_free (void *ptr) /* {{{ */
{
  fj_node_t *node = ptr;

  if (node == NULL)
    return;

  if (node->conn != NULL)
  {
    redisFree (node->conn);
    node->conn = NULL;
  }

  sfree (node->host);
  sfree (node);
} /* }}} void fj_config_free */

static int flapjack_push (char const *buffer, user_data_t *ud) /* {{{ */
{
  fj_node_t *node = ud->data;
  redisReply *rr;

  pthread_mutex_lock (&node->lock);

  if (node->conn == NULL)
  {
    node->conn = redisConnectWithTimeout ((char *)node->host, node->port, node->timeout);
    if (node->conn == NULL)
    {
      ERROR ("notify_flapjack plugin: Connecting to host \"%s\" (port %i) failed: Unkown reason",
          (node->host != NULL) ? node->host : "localhost",
          (node->port != 0) ? node->port : 6379);
      pthread_mutex_unlock (&node->lock);
      return (-1);
    }
    else if (node->conn->err)
    {
      ERROR ("notify_flapjack plugin: Connecting to host \"%s\" (port %i) failed: %s",
          (node->host != NULL) ? node->host : "localhost",
          (node->port != 0) ? node->port : 6379,
          node->conn->errstr);
      pthread_mutex_unlock (&node->lock);
      return (-1);
    }

    rr = redisCommand(node->conn, "SELECT %d", node->database);
    if (rr == NULL)
      WARNING("notify_flapjack plugin: %s:%d SELECT command error. database:%d message:%s", node->host, node->port, node->database, node->conn->errstr);
    else
      freeReplyObject (rr);
  }

  DEBUG("notify_flapjack plugin: %s:%d:%d LPUSH events %s", node->host, node->port, node->database, buffer);

  rr = redisCommand (node->conn, "LPUSH %s %s", "events", buffer);
  if (rr == NULL)
    WARNING("notify_flapjack plugin: %s:%d:%d LPUSH command error (events). message:%s", node->host, node->port, node->database, node->conn->errstr);
  else
    freeReplyObject (rr);

  if ( node->flapjack_version > 1) {
    rr = redisCommand (node->conn, "LPUSH events_actions +");
    if (rr == NULL)
      WARNING("notify_flapjack plugin: %s:%d:%d LPUSH command error (events_actions). message:%s", node->host, node->port, node->database, node->conn->errstr);
    else
      freeReplyObject (rr);
  }

  pthread_mutex_unlock (&node->lock);

  return (0);
} /* }}} int flpjack_push */

static int flapjack_notify (const notification_t *n, /* {{{ */
    __attribute__((unused)) user_data_t *ud)
{
  char svc_description[4 * DATA_MAX_NAME_LEN];
  char buffer[4096];
  char *state;
  int status;
  int written;

  status = format_name (svc_description, (int) sizeof (svc_description),
      /* host */ "", n->plugin, n->plugin_instance, n->type, n->type_instance);
  if (status != 0)
  {
    ERROR ("notify_flapjack plugin: Formatting service name failed.");
    return status;
  }

  switch (n->severity)
  {
    case NOTIF_OKAY:
      state = servicestate[0]; // OK
      break;
    case NOTIF_WARNING:
      state = servicestate[1]; // WARNING
      break;
    case NOTIF_FAILURE:
      state = servicestate[2]; // CRITICAL
      break;
    default:
      state = servicestate[3]; // UNKNOWN
      break;
  }

  long initial_failure_delay  = 0;
  long repeat_failure_delay   = 0;
  long initial_recovery_delay = 0;

  written = generate_event(buffer, sizeof (buffer),
      n->host,
      &svc_description[1],
      state,
      n->message,
      "srvchkdata->long_output",
      "", // tags
      initial_failure_delay,
      repeat_failure_delay,
      initial_recovery_delay,
      CDTIME_T_TO_DOUBLE (n->time));

  if (written >= sizeof (buffer))
  {
    WARNING ("flapjack_notify buffer too small %d %s", written, buffer);
  }
  DEBUG ("flapjack_notify %s", buffer);
  return flapjack_push (buffer, ud);
} /* }}} int flapjack_notify */

static int fj_config_node (oconfig_item_t *ci) /* {{{ */
{
  fj_node_t *node;
  int timeout;
  int status;
  int i;

  node = calloc (1, sizeof (*node));
  if (node == NULL)
    return (ENOMEM);
  node->host = NULL;
  node->port = 0;
  node->timeout.tv_sec = 0;
  node->timeout.tv_usec = 1000;
  node->conn = NULL;
  node->database = 0;
  node->flapjack_version = 2;
  pthread_mutex_init (&node->lock, /* attr = */ NULL);

  status = cf_util_get_string_buffer (ci, node->name, sizeof (node->name));
  if (status != 0)
  {
    sfree (node);
    return (status);
  }

  for (i = 0; i < ci->children_num; i++)
  {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp ("Host", child->key) == 0)
      status = cf_util_get_string (child, &node->host);
    else if (strcasecmp ("Port", child->key) == 0)
    {
      status = cf_util_get_port_number (child);
      if (status > 0)
      {
        node->port = status;
        status = 0;
      }
    }
    else if (strcasecmp ("Timeout", child->key) == 0) {
      status = cf_util_get_int (child, &timeout);
      if (status == 0) node->timeout.tv_usec = timeout;
    }
    else if (strcasecmp ("Database", child->key) == 0) {
      status = cf_util_get_int (child, &node->database);
    }
    else if (strcasecmp ("Flapjack_Version", child->key) == 0) {
      status = cf_util_get_int (child, &node->flapjack_version);
    }
    else
      WARNING ("notify_flapjack plugin: Ignoring unknown config option \"%s\".",
          child->key);

    if (status != 0)
      break;
  } /* for (i = 0; i < ci->children_num; i++) */

  if (status == 0)
  {
    char cb_name[DATA_MAX_NAME_LEN];
    user_data_t ud;

    ssnprintf (cb_name, sizeof (cb_name), "notify_flapjack/%s", node->name);

    ud.data = node;
    ud.free_func = fj_config_free;

    NOTICE ("plugin notify flapjack: %s %s:%d", cb_name,
          (node->host != NULL) ? node->host : "localhost",
          (node->port != 0) ? node->port : 6379);
    plugin_register_notification (cb_name, flapjack_notify, &ud);
  }

  if (status != 0)
    fj_config_free (node);

  return (status);
} /* }}} int fj_config_node */

static int nagios_config (oconfig_item_t *ci) /* {{{ */
{
  int i;

  for (i = 0; i < ci->children_num; i++)
  {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp ("Node", child->key) == 0)
      fj_config_node (child);
    else
      WARNING ("notify_flapjack plugin: Ignoring unknown config option \"%s\".",
          child->key);
  }

  return 0;
} /* }}} nagios_config */

void module_register (void)
{
  plugin_register_complex_config ("notify_flapjack", nagios_config);
} /* void module_register (void) */

/* vim: set sw=2 sts=2 ts=8 et : */

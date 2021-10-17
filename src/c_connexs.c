/***********************************************************************
 *          C_CONNEXS.C
 *          Connexs GClass.
 *
 *          Auto-connection and multi-destine over tcp with tls
 *
 *          Copyright (c) 2018 Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include "c_connexs.h"

/***************************************************************************
 *              Constants
 ***************************************************************************/

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/


/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------------------flag------------default---------description---------- */
SDATA (ASN_JSON,        "crypto",                       SDF_RD,         0,              "Crypto config"),

SDATA (ASN_UNSIGNED,    "connxs",                       SDF_RD,         0,              "connection counter"),
SDATA (ASN_BOOLEAN,     "connected",                    SDF_RD|SDF_STATS,0,              "Connection state. Important filter!"),

SDATA (ASN_BOOLEAN,     "manual",                       SDF_RD,         0,              "Set true if you want connect manually"),
SDATA (ASN_OCTET_STR,   "connected_event_name",         SDF_RD,         "EV_CONNECTED", "Must be empty if you don't want receive this event"),
SDATA (ASN_OCTET_STR,   "disconnected_event_name",      SDF_RD,         "EV_DISCONNECTED", "Must be empty if you don't want receive this event"),
SDATA (ASN_OCTET_STR,   "tx_ready_event_name",          SDF_RD,         "EV_TX_READY",  "Must be empty if you don't want receive this event"),
SDATA (ASN_OCTET_STR,   "rx_data_event_name",           SDF_RD,         "EV_RX_DATA",   "Must be empty if you don't want receive this event"),
SDATA (ASN_OCTET_STR,   "stopped_event_name",           SDF_RD,         "EV_STOPPED",   "Stopped event name"),
SDATA (ASN_INTEGER,     "timeout_waiting_connected",    SDF_WR|SDF_PERSIST, 60*1000,    ""),
SDATA (ASN_INTEGER,     "timeout_between_connections",  SDF_WR|SDF_PERSIST, 2*1000,     "Idle timeout to wait between attempts of connection"),
SDATA (ASN_INTEGER,     "timeout_inactivity",           SDF_WR|SDF_PERSIST, -1,
       "Inactivity timeout to close the connection."
        "Reconnect when new data arrived. With -1 never close."),
SDATA (ASN_JSON,        "urls",                         SDF_WR|SDF_PERSIST, 0,          "list of destination urls: [rUrl^lUrl, ...]"),
SDATA (ASN_OCTET_STR,   "lHost",                        SDF_RD,         0,              "Bind to a particular local ip"),
SDATA (ASN_OCTET_STR,   "lPort",                        SDF_RD,         0,              "Bind to a particular local port"),
SDATA (ASN_POINTER,     "user_data",                    0,              0,              "user data"),
SDATA (ASN_POINTER,     "user_data2",                   0,              0,              "more user data"),
SDATA (ASN_POINTER,     "subscriber",                   0,              0,              "subscriber of output-events. If it's null then subscriber is the parent."),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_DEBUG = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"debug",       "Trace"},
{0, 0},
};


/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    hgobj timer;
    int idx_dst;
    int n_urls;
    json_t *urls;
    dl_list_t dl_tx_data;
    ip_port ip_port;

    const char *connected_event_name;
    const char *tx_ready_event_name;
    const char *rx_data_event_name;
    const char *disconnected_event_name;
    const char *stopped_event_name;

    int32_t timeout_inactivity;

    uint32_t *pconnxs;

    hytls ytls;

} PRIVATE_DATA;




            /******************************
             *      Framework Methods
             ******************************/




/***************************************************************************
 *      Framework Method create
 ***************************************************************************/
PRIVATE void mt_create(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    priv->timer = gobj_create("", GCLASS_TIMER, 0, gobj);

    json_t *jn_crypto = gobj_read_json_attr(gobj, "crypto");
    priv->ytls = ytls_init(jn_crypto, FALSE);

    dl_init(&priv->dl_tx_data);

    /*
     *  CHILD subscription model
     */
    hgobj subscriber = (hgobj)gobj_read_pointer_attr(gobj, "subscriber");
    if(!subscriber) {
        subscriber = gobj_parent(gobj);
    }
    gobj_subscribe_event(gobj, NULL, NULL, subscriber);

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    priv->pconnxs = gobj_danger_attr_ptr(gobj, "connxs");
    SET_PRIV(timeout_inactivity,            gobj_read_int32_attr)
    SET_PRIV(connected_event_name,          gobj_read_str_attr)
    SET_PRIV(tx_ready_event_name,           gobj_read_str_attr)
    SET_PRIV(rx_data_event_name,            gobj_read_str_attr)
    SET_PRIV(disconnected_event_name,       gobj_read_str_attr)
    SET_PRIV(stopped_event_name,            gobj_read_str_attr)
    SET_PRIV(urls,                          gobj_read_json_attr)
    if(!json_is_array(priv->urls)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "urls MUST BE an json array!",
            NULL
        );
        log_debug_json(0, priv->urls, "urls MUST BE an json array!");
    }
    priv->n_urls = json_array_size(priv->urls);
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    IF_EQ_SET_PRIV(connected_event_name,            gobj_read_str_attr)
    ELIF_EQ_SET_PRIV(tx_ready_event_name,           gobj_read_str_attr)
    ELIF_EQ_SET_PRIV(rx_data_event_name,            gobj_read_str_attr)
    ELIF_EQ_SET_PRIV(disconnected_event_name,       gobj_read_str_attr)
    ELIF_EQ_SET_PRIV(stopped_event_name,            gobj_read_str_attr)
    ELIF_EQ_SET_PRIV(timeout_inactivity,            gobj_read_int32_attr)
    ELIF_EQ_SET_PRIV(urls,                          gobj_read_json_attr)
        if(!json_is_array(priv->urls)) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_PARAMETER_ERROR,
                "msg",          "%s", "urls MUST BE an json array!",
                NULL
            );
            log_debug_json(0, priv->urls, "urls MUST BE an json array!");
        }
        priv->n_urls = json_array_size(priv->urls);
    END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    hgobj tcp0 = gobj_bottom_gobj(gobj);
    if(!tcp0) {
        json_t *kw_tcp1 = json_pack("{s:I}", "ytls", (json_int_t)(size_t)priv->ytls);
        tcp0 = gobj_create(gobj_name(gobj), GCLASS_TCP1, kw_tcp1, gobj);
        gobj_set_bottom_gobj(gobj, tcp0);
    } else {
        gobj_write_pointer_attr(tcp0, "ytls", priv->ytls);
    }

    // HACK el start de tcp0 lo hace el timer
    gobj_start(priv->timer);
    if(!gobj_read_bool_attr(gobj, "manual")) {
        set_timeout(priv->timer, 100);
    }
    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    clear_timeout(priv->timer);
    gobj_stop(priv->timer);

    if(gobj_bottom_gobj(gobj)) {
        if(gobj_is_running(gobj_bottom_gobj(gobj))) {
            gobj_stop(gobj_bottom_gobj(gobj));
        }
    }

    return 0;
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(dl_size(&priv->dl_tx_data)>0) {
        GBUFFER *gbuf;
        while((gbuf=dl_first(&priv->dl_tx_data))) {
            dl_delete(&priv->dl_tx_data, gbuf, 0);
            gbuf_decref(gbuf);
        }
    }
    EXEC_AND_RESET(ytls_cleanup, priv->ytls);
}




            /***************************
             *      Local Methods
             ***************************/




/***************************************************************************
 *  Return the destination (host,port) tuple to connect from
 *  the ``urls`` attribute.
 *  If there are multiple urls try to connect to each cyclically.
 ***************************************************************************/
PRIVATE BOOL get_next_dst(
    hgobj gobj,
    char *schema, int schema_len,
    char *rhost, int rhost_len,
    char *rport, int rport_len,
    char *lhost, int lhost_len,
    char *lport, int lport_len
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    if(priv->n_urls) {
        // get local Host/Port from split with ^
        char *rl_url[2];
        int list_size;

        const char *url = json_list_str(priv->urls, priv->idx_dst);
        if(strchr(url, '^')) {
            list_size = split(
                url,
                "^",
                rl_url,
                2
            );
            parse_http_url(rl_url[0], schema, schema_len, rhost, rhost_len, rport, rport_len, FALSE);
            parse_http_url(rl_url[1], schema, schema_len, lhost, lhost_len, lport, lport_len, FALSE);
            split_free(rl_url, list_size);
        } else {
            parse_http_url(url, schema, schema_len, rhost, rhost_len, rport, rport_len, FALSE);
            const char *p = gobj_read_str_attr(gobj, "lHost");
            snprintf(lhost, lhost_len, "%s", p?p:"");
            p = gobj_read_str_attr(gobj, "lPort");
            snprintf(lport, lport_len, "%s", p?p:"");
        }

        // Point to next dst
        ++priv->idx_dst;
        priv->idx_dst = priv->idx_dst % priv->n_urls;
        return TRUE;
    }

    return FALSE;
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_connect(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    char schema[20], rHost[120], rPort[40], lHost[120], lPort[40];
    get_next_dst(
        gobj,
        schema, sizeof(schema),
        rHost, sizeof(rHost),
        rPort, sizeof(rPort),
        lHost, sizeof(lHost),
        lPort, sizeof(lPort)
    );
    if(empty_string(rHost)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "Not remote HOST has been configured!",
            NULL
        );
    }
    if(empty_string(rPort)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "Not remote PORT has been configured!",
            NULL
        );
    }

    /*
     *  Pass the parameters directly with a write in child attributes.
     */
    hgobj bottom_gobj = gobj_bottom_gobj(gobj);
    if(bottom_gobj) {
        gobj_write_str_attr(bottom_gobj, "lHost", lHost);
        gobj_write_str_attr(bottom_gobj, "lPort", lPort);
        gobj_write_str_attr(bottom_gobj, "rHost", rHost);
        gobj_write_str_attr(bottom_gobj, "rPort", rPort);

        set_timeout(priv->timer, gobj_read_int32_attr(gobj, "timeout_waiting_connected"));
        gobj_start(bottom_gobj);
    } else {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "NO bottom_gobj!",
            NULL
        );
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout_disconnected(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if (gobj_read_bool_attr(gobj, "manual")) {
        return 0;
    }

    if (priv->timeout_inactivity > 0) {
        // don't connect until arrives data to transmit
        if(*priv->pconnxs) {
        } else {
            // But connect once time at least.
            gobj_send_event(gobj, "EV_CONNECT", 0, gobj);
        }
    } else {
        gobj_send_event(gobj, "EV_CONNECT", 0, gobj);
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_disconnected(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_is_running(gobj)) {
        if (priv->n_urls > 0 && priv->idx_dst > 0) {
            set_timeout(priv->timer, 100);
        } else {
            set_timeout(
                priv->timer,
                gobj_read_int32_attr(gobj, "timeout_between_connections")
            );
        }
    }

    if(!empty_string(priv->disconnected_event_name)) {
        gobj_publish_event(gobj, priv->disconnected_event_name, 0);
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout_wait_connected(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    gobj_stop(gobj_bottom_gobj(gobj));

    set_timeout(
        priv->timer,
        gobj_read_int32_attr(gobj, "timeout_between_connections")
    );

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_connected(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    clear_timeout(priv->timer);

    (*priv->pconnxs)++;

    if (priv->timeout_inactivity > 0) {
        set_timeout(priv->timer, priv->timeout_inactivity);
    }

    /*
     *  process enqueued data
     */
    if(dl_size(&priv->dl_tx_data)>0) {
        GBUFFER *gbuf;
        while((gbuf=dl_first(&priv->dl_tx_data))) {
            dl_delete(&priv->dl_tx_data, gbuf, 0);

            json_t *k = json_pack("{s:I}",
                "gbuffer", (json_int_t)(size_t)gbuf
            );
            gobj_send_event(gobj_bottom_gobj(gobj), "EV_TX_DATA", k, gobj);
        }
    }

    if (!empty_string(priv->connected_event_name)) {
        gobj_publish_event(gobj, priv->connected_event_name, 0);
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_rx_data(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if (priv->timeout_inactivity > 0)
        set_timeout(priv->timer, priv->timeout_inactivity);
    gobj_publish_event(gobj, priv->rx_data_event_name, kw); // use the same kw
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout_data(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    gobj_stop(gobj_bottom_gobj(gobj));

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_tx_data(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if (priv->timeout_inactivity > 0)
        set_timeout(priv->timer, priv->timeout_inactivity);
    gobj_send_event(gobj_bottom_gobj(gobj), "EV_TX_DATA", kw, gobj); // own kw
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_enqueue_tx_data(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    GBUFFER *gbuf = (GBUFFER *)(size_t)kw_get_int(kw, "gbuffer", 0, FALSE);

    if(gbuf) {
        dl_add(&priv->dl_tx_data, gbuf);
    }
    if(gobj_in_this_state(gobj, "ST_DISCONNECTED")) {
        gobj_send_event(gobj, "EV_CONNECT", 0, gobj);
    }
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_transmit_ready(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if (!empty_string(priv->tx_ready_event_name)) {
        const char *event_name = priv->tx_ready_event_name;
        json_t *kw_ex = json_pack("{s:I}",
            "connex", (json_int_t)(size_t)gobj
        );
        gobj_publish_event(gobj, event_name, kw_ex);
    }
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_ignore_transmit_ready(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_drop(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_is_running(gobj_bottom_gobj(gobj))) {
        set_timeout(
            priv->timer,
            gobj_read_int32_attr(gobj, "timeout_between_connections")
        );
        gobj_stop(gobj_bottom_gobj(gobj));
    }

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_stopped(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_bottom_gobj(gobj)==src) {
        if(gobj_is_running(gobj)) {
            if (priv->n_urls > 0 && priv->idx_dst > 0) {
                set_timeout(priv->timer, 100);
            } else {
                set_timeout(
                    priv->timer,
                    gobj_read_int32_attr(gobj, "timeout_between_connections")
                );
            }
        }
    }

    KW_DECREF(kw);
    return 0;
}


/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    {"EV_CONNECTED",        0},
    {"EV_DISCONNECTED",     0},
    {"EV_RX_DATA",          0},
    {"EV_TX_READY",         0},
    {"EV_STOPPED",          0},

    {"EV_DROP",             0},
    {"EV_CONNECT",          0},
    {"EV_TX_DATA",          0},

    {"EV_TIMEOUT",          0},
    {NULL, 0}
};
PRIVATE const EVENT output_events[] = {
    {"EV_CONNECTED",        0},
    {"EV_DISCONNECTED",     0},
    {"EV_RX_DATA",          0},
    {"EV_TX_READY",         0},
    {"EV_STOPPED",          0},
    {NULL, 0}
};
PRIVATE const char *state_names[] = {
    "ST_DISCONNECTED",
    "ST_WAIT_CONNECTED",
    "ST_CONNECTED",
    "ST_WAIT_DISCONNECTED",
    NULL
};

PRIVATE EV_ACTION ST_DISCONNECTED[] = {
    {"EV_CONNECT",          ac_connect,                 "ST_WAIT_CONNECTED"},
    {"EV_TX_DATA",          ac_enqueue_tx_data,         0},
    {"EV_TIMEOUT",          ac_timeout_disconnected,    0},
    {"EV_STOPPED",          ac_stopped,                 0},
    {0,0,0}
};
PRIVATE EV_ACTION ST_WAIT_CONNECTED[] = {
    {"EV_TX_DATA",          ac_enqueue_tx_data,         0},
    {"EV_CONNECTED",        ac_connected,               "ST_CONNECTED"},
    {"EV_DISCONNECTED",     ac_disconnected,            "ST_DISCONNECTED"},
    {"EV_STOPPED",          ac_stopped,                 "ST_DISCONNECTED"},
    {"EV_TIMEOUT",          ac_timeout_wait_connected,  "ST_DISCONNECTED"},
    {"EV_DROP",             ac_drop,                    "ST_WAIT_DISCONNECTED"},
    {"EV_TX_READY",         ac_ignore_transmit_ready,   0},
    {0,0,0}
};
PRIVATE EV_ACTION ST_CONNECTED[] = {
    {"EV_RX_DATA",          ac_rx_data,                 0},
    {"EV_TX_DATA",          ac_tx_data,                 0},
    {"EV_DISCONNECTED",     ac_disconnected,            "ST_DISCONNECTED"},
    {"EV_TIMEOUT",          ac_timeout_data,            0},
    {"EV_TX_READY",         ac_transmit_ready,          0},
    {"EV_DROP",             ac_drop,                    "ST_WAIT_DISCONNECTED"},
    {"EV_STOPPED",          ac_stopped,                 0},
    {0,0,0}
};
PRIVATE EV_ACTION ST_WAIT_DISCONNECTED[] = {
    {"EV_DISCONNECTED",     ac_disconnected,            "ST_DISCONNECTED"},
    {"EV_STOPPED",          ac_stopped,                 "ST_DISCONNECTED"},
    {"EV_TIMEOUT",          ac_stopped,                 "ST_DISCONNECTED"},
    {"EV_TX_READY",         ac_ignore_transmit_ready,   0},
    {0,0,0}
};


PRIVATE EV_ACTION *states[] = {
    ST_DISCONNECTED,
    ST_WAIT_CONNECTED,
    ST_CONNECTED,
    ST_WAIT_DISCONNECTED,
    NULL
};

PRIVATE FSM fsm = {
    input_events,
    output_events,
    state_names,
    states,
};

/***************************************************************************
 *              GClass
 ***************************************************************************/
/*---------------------------------------------*
 *              Local methods table
 *---------------------------------------------*/
PRIVATE LMETHOD lmt[] = {
    {0, 0, 0}
};

/*---------------------------------------------*
 *              GClass
 *---------------------------------------------*/
PRIVATE GCLASS _gclass = {
    0,  // base
    GCLASS_CONNEXS_NAME,
    &fsm,
    {
        mt_create,
        0, //mt_create2,
        mt_destroy,
        mt_start,
        mt_stop,
        0, //mt_play,
        0, //mt_pause,
        mt_writing,
        0, //mt_reading,
        0, //mt_subscription_added,
        0, //mt_subscription_deleted,
        0, //mt_child_added,
        0, //mt_child_removed,
        0, //mt_stats,
        0, //mt_command_parser,
        0, //mt_inject_event,
        0, //mt_create_resource,
        0, //mt_list_resource,
        0, //mt_update_resource,
        0, //mt_delete_resource,
        0, //mt_add_child_resource_link
        0, //mt_delete_child_resource_link
        0, //mt_get_resource
        0, //mt_authorization_parser,
        0, //mt_authenticate,
        0, //mt_list_childs,
        0, //mt_stats_updated,
        0, //mt_disable,
        0, //mt_enable,
        0, //mt_trace_on,
        0, //mt_trace_off,
        0, //mt_gobj_created,
        0, //mt_future33,
        0, //mt_future34,
        0, //mt_publish_event,
        0, //mt_publication_pre_filter,
        0, //mt_publication_filter,
        0, //mt_authz_checker,
        0, //mt_future39,
        0, //mt_create_node,
        0, //mt_update_node,
        0, //mt_delete_node,
        0, //mt_link_nodes,
        0, //mt_future44,
        0, //mt_unlink_nodes,
        0, //mt_topic_jtree,
        0, //mt_get_node,
        0, //mt_list_nodes,
        0, //mt_shoot_snap,
        0, //mt_activate_snap,
        0, //mt_list_snaps,
        0, //mt_treedbs,
        0, //mt_treedb_topics,
        0, //mt_topic_desc,
        0, //mt_topic_links,
        0, //mt_topic_hooks,
        0, //mt_node_parents,
        0, //mt_node_childs,
        0, //mt_list_instances,
        0, //mt_node_tree,
        0, //mt_topic_size,
        0, //mt_future62,
        0, //mt_future63,
        0, //mt_future64
    },
    lmt,
    tattr_desc,
    sizeof(PRIVATE_DATA),
    0,  // acl
    s_user_trace_level,
    0,  // cmds
    0,  // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_connexs(void)
{
    return &_gclass;
}

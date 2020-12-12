/***********************************************************************
 *          C_AUTHZ.C
 *          Authz GClass.
 *
 *          Authorization Manager
 *
 *          Copyright (c) 2020 Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <string.h>
#include <stdio.h>
#include <cjose/cjose.h>
#include <oauth2/oauth2.h>
#include <oauth2/mem.h>
#include <uuid/uuid.h>
#include "c_authz.h"

#include "treedb_schema_authzs.c"

/***************************************************************************
 *              Constants
 ***************************************************************************/

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/
PRIVATE void oauth2_log_callback(
    oauth2_log_sink_t *sink,
    const char *filename,
    unsigned long line,
    const char *function,
    oauth2_log_level_t level,
    const char *msg
);

/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE sdata_desc_t pm_help[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "cmd",          0,              0,          "command about you want help."),
SDATAPM (ASN_UNSIGNED,  "level",        0,              0,          "command search level in childs"),
SDATA_END()
};

PRIVATE const char *a_help[] = {"h", "?", 0};

PRIVATE sdata_desc_t command_table[] = {
/*-CMD---type-----------name----------------alias---------------items-----------json_fn---------description---------- */
SDATACM (ASN_SCHEMA,    "help",             a_help,             pm_help,        cmd_help,       "Command's help"),
SDATA_END()
};

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------flag----------------default---------description---------- */
SDATA (ASN_OCTET_STR,   "jwt_public_key",   SDF_RD,             0,          "JWT public key"),

SDATA (ASN_COUNTER64,   "txMsgs",           SDF_RD|SDF_PSTATS,  0,          "Messages transmitted"),
SDATA (ASN_COUNTER64,   "rxMsgs",           SDF_RD|SDF_RSTATS,  0,          "Messages receiveds"),

SDATA (ASN_COUNTER64,   "txMsgsec",         SDF_RD|SDF_RSTATS,  0,          "Messages by second"),
SDATA (ASN_COUNTER64,   "rxMsgsec",         SDF_RD|SDF_RSTATS,  0,          "Messages by second"),
SDATA (ASN_COUNTER64,   "maxtxMsgsec",      SDF_WR|SDF_RSTATS,  0,          "Max Tx Messages by second"),
SDATA (ASN_COUNTER64,   "maxrxMsgsec",      SDF_WR|SDF_RSTATS,  0,          "Max Rx Messages by second"),

SDATA (ASN_INTEGER,     "timeout",          SDF_RD,             1*1000,     "Timeout"),
SDATA (ASN_POINTER,     "user_data",        0,                  0,          "user data"),
SDATA (ASN_POINTER,     "user_data2",       0,                  0,          "more user data"),
SDATA (ASN_POINTER,     "subscriber",       0,                  0,          "subscriber of output-events. Not a child gobj."),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *  HACK strict ascendent value!
 *  required paired correlative strings
 *  in s_user_trace_level
 *---------------------------------------------*/
enum {
    TRACE_MESSAGES = 0x0001,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"messages",        "Trace messages"},
{0, 0},
};

/*---------------------------------------------*
 *      GClass authz levels
 *---------------------------------------------*/
PRIVATE sdata_desc_t pm_authz_sample[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "param",        0,              0,          "Param ..."),
SDATA_END()
};

PRIVATE sdata_desc_t authz_table[] = {
/*-AUTHZ-- type---------name------------flag----alias---items---------------description--*/
SDATAAUTHZ (ASN_SCHEMA, "sample",       0,      0,      pm_authz_sample,    "Permission to ..."),
SDATA_END()
};

/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    hgobj timer;
    int32_t timeout;

    oauth2_log_t *oath2_log;
    oauth2_log_sink_t *oath2_sink;

    hgobj gobj_tranger;
    hgobj treedb_authz;
    json_t *tranger;
    json_t *users_accesses;

    uint64_t *ptxMsgs;
    uint64_t *prxMsgs;
    uint64_t txMsgsec;
    uint64_t rxMsgsec;
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

    helper_quote2doublequote(treedb_schema_authzs);

    /*
     *  Chequea schema fichador, exit si falla.
     */
    json_t *jn_treedb_schema_authzs;
    jn_treedb_schema_authzs = legalstring2json(treedb_schema_authzs, TRUE);
    if(!jn_treedb_schema_authzs) {
        exit(-1);
    }

    int level = OAUTH2_LOG_WARN;
    priv->oath2_sink = oauth2_log_sink_create(
        level,                  // oauth2_log_level_t level,
        oauth2_log_callback,    // oauth2_log_function_t callback,
        gobj                    // void *ctx
    );
    priv->oath2_log = oauth2_log_init(level, priv->oath2_sink);

    priv->timer = gobj_create(gobj_name(gobj), GCLASS_TIMER, 0, gobj);
    priv->ptxMsgs = gobj_danger_attr_ptr(gobj, "txMsgs");
    priv->prxMsgs = gobj_danger_attr_ptr(gobj, "rxMsgs");

    /*---------------------------*
     *  Create Timeranger
     *---------------------------*/
    char path[PATH_MAX];
    snprintf(path, sizeof(path),
        "/yuneta/store/realms/%s/%s/authzs",
        gobj_yuno_realm_name(),
        gobj_yuno_role_plus_name()
    );
    json_t *kw_tranger = json_pack("{s:s, s:s, s:b, s:i}",
        "path", path,
        "filename_mask", "%Y",
        "master", 1,
        "on_critical_error", (int)(LOG_OPT_EXIT_ZERO)
    );
    priv->gobj_tranger = gobj_create_service(
        "tranger",
        GCLASS_TRANGER,
        kw_tranger,
        gobj
    );

    /*----------------------*
     *  Create Treedb
     *----------------------*/
//     const char *treedb_name = kw_get_str(
//         jn_schema_gest_controlcenter,
//         "id",
//         "gest_controlcenter",
//         KW_REQUIRED
//     );
//     json_t *kw_resource = json_pack("{s:s, s:o, s:i}",
//         "treedb_name", treedb_name,
//         "treedb_schema", jn_schema_gest_controlcenter,
//         "exit_on_error", LOG_OPT_EXIT_ZERO
//     );
//
//     priv->treedb_gest = gobj_create_service(
//         treedb_name,
//         GCLASS_NODE,
//         kw_resource,
//         gobj
//     );

    /*
     *  SERVICE subscription model
     */
    hgobj subscriber = (hgobj)gobj_read_pointer_attr(gobj, "subscriber");
    if(subscriber) {
        gobj_subscribe_event(gobj, NULL, NULL, subscriber);
    }

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(timeout,               gobj_read_int32_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    IF_EQ_SET_PRIV(timeout,             gobj_read_int32_attr)
    END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    gobj_start(priv->timer);
    set_timeout_periodic(priv->timer, priv->timeout);
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
    return 0;
}




            /***************************
             *      Commands
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    KW_INCREF(kw);
    json_t *jn_resp = gobj_build_cmds_doc(gobj, kw);
    return msg_iev_build_webix(
        gobj,
        0,
        jn_resp,
        0,
        0,
        kw  // owned
    );
}




            /***************************
             *      Local Methods
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE void oauth2_log_callback(
    oauth2_log_sink_t *sink,
    const char *filename,
    unsigned long line,
    const char *function,
    oauth2_log_level_t level,
    const char *msg
)
{
    hgobj gobj = oauth2_log_sink_ctx_get(sink);

    void (*log_fn)(log_opt_t opt, ...) = 0;
    const char *msgset = MSGSET_OAUTH_ERROR;

    if(level == OAUTH2_LOG_ERROR) {
        log_fn = log_error;
    } else if(level == OAUTH2_LOG_WARN) {
        log_fn = log_warning;
    } else if(level == OAUTH2_LOG_NOTICE || level == OAUTH2_LOG_INFO) {
        log_fn = log_warning;
        msgset = MSGSET_INFO;
    } else if(level >= OAUTH2_LOG_DEBUG) {
        log_fn = log_debug;
        msgset = MSGSET_INFO;
    }

    log_fn(0,
        "gobj",             "%s", gobj_full_name(gobj),
        "function",         "%s", function,
        "msgset",           "%s", msgset,
        "msg",              "%s", msg,
        NULL
    );
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_sample(hgobj gobj, const char *event, json_t *kw, hgobj src)
{

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout(hgobj gobj, const char *event, json_t *kw, hgobj src)
{

    KW_DECREF(kw);
    return 0;
}


/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    // top input
    {"EV_SAMPLE",       0,  0,  "Description of resource"},
    // bottom input
    {"EV_TIMEOUT",      0,  0,  ""},
    // internal
    {NULL, 0, 0, ""}
};
PRIVATE const EVENT output_events[] = {
    {"EV_ON_SAMPLE1",       0,  0,  "Sample1"},
    {"EV_ON_SAMPLE2",       0,  0,  "Sample2"},
    {NULL, 0, 0, ""}
};
PRIVATE const char *state_names[] = {
    "ST_IDLE",
    NULL
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_SAMPLE",               ac_sample,              0},
    {"EV_TIMEOUT",              ac_timeout,             0},
    {0,0,0}
};

PRIVATE EV_ACTION *states[] = {
    ST_IDLE,
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
    GCLASS_AUTHZ_NAME,
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
        0, //mt_authz_allow,
        0, //mt_authz_deny,
        0, //mt_publish_event,
        0, //mt_publication_pre_filter,
        0, //mt_publication_filter,
        0, //mt_future38,
        0, //mt_future39,
        0, //mt_create_node,
        0, //mt_update_node,
        0, //mt_delete_node,
        0, //mt_link_nodes,
        0, //mt_link_nodes2,
        0, //mt_unlink_nodes,
        0, //mt_unlink_nodes2,
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
        0, //mt_node_instances,
        0, //mt_save_node,
        0, //mt_future61,
        0, //mt_future62,
        0, //mt_future63,
        0, //mt_future64
    },
    lmt,
    tattr_desc,
    sizeof(PRIVATE_DATA),
    authz_table,
    s_user_trace_level,
    command_table,  // command_table
    0,  // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_authz(void)
{
    return &_gclass;
}

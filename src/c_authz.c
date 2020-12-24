/***********************************************************************
 *          C_AUTHZ.C
 *          Authz GClass.
 *
 *          Authorization Manager
 *
 *          Copyright (c) 2020 Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
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
PRIVATE int create_new_user(hgobj gobj, const char *username, json_t *jwt_payload);

PRIVATE json_t *identify_system_user(
    hgobj gobj,
    const char *username,
    BOOL include_groups,
    BOOL verbose
);

PRIVATE json_t *get_user_roles(
    hgobj gobj,
    const char *username,
    json_t *kw  // not owned
);

/***************************************************************************
 *              Resources
 ***************************************************************************/
PRIVATE topic_desc_t db_messages_desc[] = {
    // Topic Name,          Pkey            System Flag     Tkey        Topic Json Desc
    {"users_accesses",      "username",     sf_string_key,  "tm",       0},
    {0}
};

/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_authzs(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE sdata_desc_t pm_help[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "cmd",          0,              0,          "command about you want help."),
SDATAPM (ASN_UNSIGNED,  "level",        0,              0,          "command search level in childs"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_authzs[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "authz",        0,              0,          "authz about you want help"),
SDATA_END()
};

PRIVATE const char *a_help[] = {"h", "?", 0};

PRIVATE sdata_desc_t command_table[] = {
/*-CMD---type-----------name----------------alias---------------items-----------json_fn---------description---------- */
SDATACM (ASN_SCHEMA,    "help",             a_help,             pm_help,        cmd_help,       "Command's help"),
SDATACM (ASN_SCHEMA,    "authzs",           0,                  pm_authzs,      cmd_authzs,     "Authorization's help"),
SDATA_END()
};

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------flag----------------default---------description---------- */
SDATA (ASN_INTEGER,     "max_sessions_per_user",SDF_PERSIST,    1,              "Max sessions per user"),
SDATA (ASN_OCTET_STR,   "jwt_public_key",   SDF_RD,             0,              "JWT public key"),
SDATA (ASN_JSON,        "initial_load",     SDF_RD,             0,              "Initial data for treedb"),
SDATA (ASN_INTEGER,     "timeout",          SDF_RD,             1*1000,         "Timeout"),
SDATA (ASN_COUNTER64,   "txMsgs",           SDF_RD|SDF_PSTATS,  0,              "Messages transmitted"),
SDATA (ASN_COUNTER64,   "rxMsgs",           SDF_RD|SDF_RSTATS,  0,              "Messages receiveds"),

SDATA (ASN_COUNTER64,   "txMsgsec",         SDF_RD|SDF_RSTATS,  0,              "Messages by second"),
SDATA (ASN_COUNTER64,   "rxMsgsec",         SDF_RD|SDF_RSTATS,  0,              "Messages by second"),
SDATA (ASN_COUNTER64,   "maxtxMsgsec",      SDF_WR|SDF_RSTATS|SDF_AUTHZ_W, 0,   "Max Tx Messages by second"),
SDATA (ASN_COUNTER64,   "maxrxMsgsec",      SDF_WR|SDF_RSTATS|SDF_AUTHZ_W, 0,   "Max Rx Messages by second"),
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
/*-PM-----type--------------name----------------flag------------description---------- */
SDATAPM0 (ASN_OCTET_STR,    "param sample",     0,              "Param ..."),
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
    int32_t timeout;
    int32_t max_sessions_per_user;
    hgobj timer;
    uint64_t *ptxMsgs;
    uint64_t *prxMsgs;
    uint64_t txMsgsec;
    uint64_t rxMsgsec;

    hgobj gobj_tranger;
    hgobj gobj_treedb;
    json_t *tranger;

    oauth2_log_t *oath2_log;
    oauth2_log_sink_t *oath2_sink;
    oauth2_cfg_token_verify_t *verify;
    json_t *users_accesses;      // dict with users opened

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
    json_t *jn_treedb_schema = legalstring2json(treedb_schema_authzs, TRUE);
    if(!jn_treedb_schema) {
        exit(-1);
    }

    priv->timer = gobj_create(gobj_name(gobj), GCLASS_TIMER, 0, gobj);
    priv->ptxMsgs = gobj_danger_attr_ptr(gobj, "txMsgs");
    priv->prxMsgs = gobj_danger_attr_ptr(gobj, "rxMsgs");

    /*---------------------------*
     *      Oauth
     *---------------------------*/
    #define MY_CACHE_OPTIONS "options=max_entries%3D10"
    int level = OAUTH2_LOG_WARN;
    priv->oath2_sink = oauth2_log_sink_create(
        level,                  // oauth2_log_level_t level,
        oauth2_log_callback,    // oauth2_log_function_t callback,
        gobj                    // void *ctx
    );
    priv->oath2_log = oauth2_log_init(level, priv->oath2_sink);

    const char *pubkey = gobj_read_str_attr(gobj, "jwt_public_key");
    if(pubkey) {
        const char *rv = oauth2_cfg_token_verify_add_options(
            priv->oath2_log, &priv->verify, "pubkey", pubkey,
            "verify.exp=skip&verify.cache." MY_CACHE_OPTIONS);
        if(rv != NULL) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_OAUTH_ERROR,
                "msg",          "%s", "oauth2_cfg_token_verify_add_options() FAILED",
                NULL
            );
        }
    }

    /*---------------------------*
     *  Create Timeranger
     *---------------------------*/
    char subpath[NAME_MAX];
    snprintf(subpath, sizeof(subpath),
        "%s/%s",
        gobj_yuno_realm_domain(),
        gobj_yuno_role_plus_name()
    );
    char path[PATH_MAX];
    yuneta_store_dir(path, sizeof(path), "authzs", subpath, TRUE);
    json_t *kw_tranger = json_pack("{s:s, s:s, s:b}",
        "path", path,
        "filename_mask", "%Y",
        "master", 1
    );
    priv->gobj_tranger = gobj_create_service(
        "tranger_authz",
        GCLASS_TRANGER,
        kw_tranger,
        gobj
    );
    priv->tranger = gobj_read_pointer_attr(priv->gobj_tranger, "tranger");

    /*----------------------*
     *  Create Treedb
     *----------------------*/
    const char *treedb_name = kw_get_str(
        jn_treedb_schema,
        "id",
        "authzs",
        KW_REQUIRED
    );
    json_t *kw_resource = json_pack("{s:I, s:s, s:o, s:i}",
        "tranger", (json_int_t)(size_t)priv->tranger,
        "treedb_name", treedb_name,
        "treedb_schema", jn_treedb_schema,
        "exit_on_error", LOG_OPT_EXIT_ZERO
    );

    priv->gobj_treedb = gobj_create_service(
        treedb_name,
        GCLASS_NODE,
        kw_resource,
        gobj
    );

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
    SET_PRIV(max_sessions_per_user, gobj_read_int32_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    IF_EQ_SET_PRIV(timeout,                 gobj_read_int32_attr)
    ELIF_EQ_SET_PRIV(max_sessions_per_user, gobj_read_int32_attr)
    END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->verify) {
        oauth2_cfg_token_verify_free(priv->oath2_log, priv->verify);
        priv->verify = 0;
    }
    EXEC_AND_RESET(oauth2_log_free, priv->oath2_log);
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    gobj_start(priv->gobj_tranger);
    priv->tranger = gobj_read_pointer_attr(priv->gobj_tranger, "tranger");

    gobj_write_pointer_attr(priv->gobj_treedb, "tranger", priv->tranger);
    gobj_start(priv->gobj_treedb);

    if(gobj_topic_size(priv->gobj_treedb, "roles")==0 &&
        gobj_topic_size(priv->gobj_treedb, "users")==0 &&
        gobj_topic_size(priv->gobj_treedb, "authorizations")==0
    ) {
        /*------------------------------------*
         *  Empty treedb? initialize treedb
         *-----------------------------------*/
        json_t *initial_load = gobj_read_json_attr(gobj, "initial_load");
        const char *topic_name;
        json_t *topic_records;
        json_object_foreach(initial_load, topic_name, topic_records) {
            int idx; json_t *record;
            json_array_foreach(topic_records, idx, record) {
                json_t *kw_update_node = json_pack("{s:s, s:O, s:{s:b}}",
                    "topic_name", topic_name,
                    "record", record,
                    "options",
                        "create", 1
                );
                gobj_send_event(
                    priv->gobj_treedb,
                    "EV_TREEDB_UPDATE_NODE",
                    kw_update_node,
                    gobj
                );
            }
        }
    }

    /*---------------------------*
     *  Open topics as messages
     *---------------------------*/
    trmsg_open_topics(
        priv->tranger,
        db_messages_desc
    );

    /*
     *  To open users accesses
     */
    priv->users_accesses = trmsg_open_list(
        priv->tranger,
        "users_accesses",   // topic
        json_pack("{s:i}",  // filter
            "max_key_instances", 1
        )
    );

    /*
     *  Periodic timer for tasks
     *  NOO, chequea bien, se lleva mal con libuv
     */
    //gobj_start(priv->timer);
    //set_timeout_periodic(priv->timer, priv->timeout);

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

    gobj_stop(priv->gobj_treedb);
    gobj_stop(priv->gobj_tranger);

    priv->tranger = 0;

    return 0;
}

/***************************************************************************
 *      Framework Method mt_authenticate
 ***************************************************************************/
PRIVATE json_t *mt_authenticate(hgobj gobj, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    const char *peername = gobj_read_str_attr(src, "peername");
    const char *jwt= kw_get_str(kw, "jwt", "", 0);
    const char *username = "";

    if(empty_string(jwt)) {
        /*-------------------------------*
         *  Without JWT, check local
         *-------------------------------*/
        if(is_ip_denied(peername)) {
            /*
             *  IP autorizada sin user/passw, informa
             */
            KW_DECREF(kw);
            return json_pack("{s:i, s:s}",
                "result", -1,
                "comment", "Ip denied"
            );
        }
        struct passwd *pw = getpwuid(getuid());
        username = pw->pw_name;

        json_t *user = identify_system_user(gobj, username, TRUE, FALSE);
        if(!user) {
            KW_DECREF(kw);
            return json_pack("{s:i, s:s, s:s}",
                "result", -1,
                "comment", "System user not found",
                "username", username
            );
        }

        json_t *access_roles = get_user_roles(gobj, username, kw);

        if(is_ip_allowed(peername)) {
            /*
             *  IP autorizada sin user/passw, usa logged user
             */
            KW_DECREF(kw);
            return json_pack("{s:i, s:s, s:s, s:o}",
                "result", 0,
                "comment", "Ip allowed",
                "username", username,
                "access_roles", access_roles
            );
        }

        const char *localhost = "127.0.0.";
        if(strncmp(peername, localhost, strlen(localhost))==0) {
            /*
             *  LOCALHOST Autorizado, informa
             */
            KW_DECREF(kw);
            return json_pack("{s:i, s:s, s:s, s:o}",
                "result", 0,
                "comment", "Ip local allowed",
                "username", username,
                "access_roles", access_roles
            );
        }
        json_decref(access_roles);

        /*
         *  Reject, Need auth
         */
        KW_DECREF(kw);
        return json_pack("{s:i, s:s}",
            "result", -1,
            "comment", "JWT is needed to authenticate"
        );
    }

    /*-------------------------------*
     *      Check user JWT
     *-------------------------------*/
    json_t *jwt_payload = NULL;
    if(!oauth2_token_verify(priv->oath2_log, priv->verify, jwt, &jwt_payload)) {
        JSON_DECREF(jwt_payload);
        KW_DECREF(kw);
        return json_pack("{s:i, s:s}",
            "result", -1,
            "comment", "JWT validation failure"
        );
    }

    /*-------------------------------------------------*
     *  Get username and validate against our system
     *-------------------------------------------------*/
    // WARNING "preferred_username" is used in keycloak! In others Oauth???
    username = kw_get_str(jwt_payload, "preferred_username", 0, KW_REQUIRED);
    json_t *user = gobj_get_node(priv->gobj_treedb, "users", username, 0, gobj);
    if(!user) {
        JSON_DECREF(jwt_payload);
        KW_DECREF(kw);
        return json_pack("{s:i, s:s, s:s}",
            "result", -1,
            "comment", "User not found",
            "username", username
        );
    }

    /*------------------------------------------------*
     *  HACK guarda jwt_payload en src (IEvent_srv)
     *------------------------------------------------*/
    gobj_write_json_attr(src, "jwt_payload", jwt_payload);
    gobj_write_str_attr(src, "__username__", username);

    /*------------------------------*
     *      Save user access
     *------------------------------*/
    json_t *user_access = trmsg_get_active_message(priv->users_accesses, username);
    if(!user_access) {
        create_new_user(gobj, username, jwt_payload);
        user_access = trmsg_get_active_message(priv->users_accesses, username);
    }
    kw_get_dict(user_access, "_sessions", json_object(), KW_CREATE);

    /*--------------------------------------------*
     *  Get sessions, check max sessions allowed
     *--------------------------------------------*/
    json_t *sessions = kw_get_dict(user, "_sessions", 0, KW_REQUIRED);
    json_t *session;
    void *n; const char *k;
    json_object_foreach_safe(sessions, n, k, session) {
        if(json_object_size(sessions) <= priv->max_sessions_per_user) {
            break;
        }
        /*-------------------------------*
         *  Check max sessions allowed
         *  Drop the old sessions
         *-------------------------------*/
        hgobj prev_channel_gobj = (hgobj)(size_t)kw_get_int(session, "channel_gobj", 0, KW_REQUIRED);
        log_info(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INFO,
            "msg",          "%s", "Drop session, max sessions reached",
            "user",         "%s", username,
            NULL
        );
        gobj_send_event(prev_channel_gobj, "EV_DROP", 0, gobj);
        json_object_del(sessions, k);
    }

    /*-------------------------------*
     *      Save session
     *  WARNING "session_state" is from keycloak!!!
     *  And others???
     *-------------------------------*/
    const char *session_id = kw_get_str(jwt_payload, "session_state", 0, KW_REQUIRED);
    session = json_pack("{s:I}",
        "channel_gobj", (json_int_t)(size_t)src
    );
    json_object_set_new(sessions, session_id, session);

    /*------------------------------------*
     *  Subscribe to know close session
     *------------------------------------*/
    gobj_subscribe_event(src, "EV_ON_CLOSE", 0, gobj);

    /*------------------------------*
     *      Get user roles
     *------------------------------*/
    json_t *access_roles = get_user_roles(gobj, username, kw);

    /*--------------------------------*
     *      Autorizado, informa
     *--------------------------------*/
    JSON_DECREF(jwt_payload);
    KW_DECREF(kw);
    return json_pack("{s:i, s:s, s:s, s:o}",
        "result", 0,
        "comment", "JWT User authenticated",
        "username", username,
        "access_roles", access_roles
    );
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

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_authzs(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    return gobj_build_authzs_doc(gobj, cmd, kw, src);
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

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *identify_system_user(
    hgobj gobj,
    const char *username,
    BOOL include_groups,
    BOOL verbose
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *user = gobj_get_node(priv->gobj_treedb, "users", username, 0, gobj);
    if(user) {
        return user;
    }

    if(include_groups) {
        /*-------------------------------*
         *  HACK user's group is valid
         *-------------------------------*/
        gid_t groups[10];
        int ngroups = sizeof(groups)/sizeof(groups[0]);

        getgrouplist(username, 0, groups, &ngroups);
        for(int i=0; i<ngroups; i++) {
            struct group *gr = getgrgid(groups[i]);
            if(gr) {
                user = gobj_get_node(priv->gobj_treedb, "users", gr->gr_name, 0, gobj);
                if(user) {
                    return user;
                }
            }
        }
    }

    if(verbose) {
        log_warning(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INFO,
            "msg",          "%s", "username not found in system",
            "username",     "%s", username,
            NULL
        );
    }
    return 0; // username as user or group not found
}

/***************************************************************************
 *
    Hay que responder al frontend:

        "access_roles": {
            "fichajes": [
                "user"
            ]
        }

 ***************************************************************************/
PRIVATE json_t *get_user_roles(
    hgobj gobj,
    const char *username,
    json_t *kw // not owned
)
{
    const char *iev_dst_yuno = kw_get_str(kw, "dst_yuno", "", 0);
    const char *iev_dst_role = kw_get_str(kw, "dst_role", "", 0);
    const char *iev_dst_service = kw_get_str(kw, "dst_service", "", 0);

    // TODO
    const char *service_name = "fichajes";

    json_t *access_roles = json_object();

    json_t *service_roles = kw_get_list(access_roles, service_name, json_array(), KW_CREATE);
    json_array_append_new(service_roles, json_string("owner"));

    return access_roles;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int create_new_user(hgobj gobj, const char *username, json_t *jwt_payload)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*
     *  Crea user en users_accesses
     */
    json_t *user = json_pack("{s:s, s:s, s:I, s:O}",
        "ev", "new_user",
        "username", username,
        "tm", (json_int_t)time_in_seconds(),
        "jwt_payload", jwt_payload
    );

    trmsg_add_instance(
        priv->tranger,
        "users_accesses",
        user, // owned
        0,
        0
    );

    user = trmsg_get_active_message(priv->users_accesses, username);

    return 0;
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *  Identity_card off from
 *      Web clients (__top_side__)
 ***************************************************************************/
PRIVATE int ac_on_close(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*------------------------------*
    *      Get jwt info
    *------------------------------*/
    json_t *jwt_payload = gobj_read_json_attr(src, "jwt_payload");
    if(!jwt_payload) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "What fuck! open without jwt_payload",
            NULL
        );
        KW_DECREF(kw);
        return 0;
    }

    /*--------------------------------------------*
     *  Add logout user
     *--------------------------------------------*/
    if(priv->tranger) { // Si han pasado a pause es 0
        const char *session_id = kw_get_str(jwt_payload, "session_state", 0, KW_REQUIRED);
        const char *username = kw_get_str(jwt_payload, "preferred_username", 0, KW_REQUIRED);
        json_t *user_ = trmsg_get_active_message(priv->users_accesses, username);
        if(!user_) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "What fuck! user not found",
                "username",          "%s", username,
                NULL
            );
        }
        json_t *user = json_deep_copy(user_);
        json_t *sessions = kw_get_dict(user, "_sessions", 0, KW_REQUIRED);
        json_t *session = kw_get_dict(sessions, session_id, 0, KW_EXTRACT); // Remove session
        JSON_DECREF(session);

        json_object_set_new(user, "ev", json_string("logout"));
        json_object_set_new(user, "tm", json_integer(time_in_seconds()));

        /*
         *  Save logout record
         */
        trmsg_add_instance(
            priv->tranger,
            "users_accesses",
            user, // owned
            0,
            0
        );
    }

    gobj_unsubscribe_event(src, "EV_ON_CLOSE", 0, gobj);

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
    // bottom input
    {"EV_ON_CLOSE",     0,  0,  ""},
    {"EV_TIMEOUT",      0,  0,  ""},
    {"EV_STOPPED",      0,  0,  ""},
    // internal
    {NULL, 0, 0, ""}
};
PRIVATE const EVENT output_events[] = {
    {NULL, 0, 0, ""}
};
PRIVATE const char *state_names[] = {
    "ST_IDLE",
    NULL
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_ON_CLOSE",             ac_on_close,            0},
    {"EV_TIMEOUT",              ac_timeout,             0},
    {"EV_STOPPED",              0,                      0},
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
        mt_authenticate,
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
        0, //mt_topic_size,
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

/***************************************************************************
   Check user authz
 ***************************************************************************/
PUBLIC BOOL authz_checker(hgobj gobj_to_check, const char *authz, json_t *kw, hgobj src)
{
    hgobj gobj = gobj_find_gclass_service(GCLASS_AUTHZ_NAME, TRUE);
    if(!gobj) {
        /*
         *  HACK if this function is called is because the authz system is configured in setup.
         *  If the service is not found deny all.
         */
        return FALSE;
    }

    json_t *authzs_list = gobj_authzs(gobj_to_check, authz);

    print_json2("=====================>", authzs_list); // TODO

    JSON_DECREF(authzs_list);
    KW_DECREF(kw);
    return TRUE;
}

/***************************************************************************
   Authenticate user
   If we are here is because gobj_service has not authenticate parser,
   then use this global parser
 ***************************************************************************/
PUBLIC json_t *authenticate_parser(hgobj gobj_service, json_t *kw, hgobj src)
{
    hgobj gobj = gobj_find_gclass_service(GCLASS_AUTHZ_NAME, TRUE);
    if(!gobj) {
        /*
         *  HACK if this function is called is because the authz system is configured in setup.
         *  If the service is not found deny all.
         */
        KW_DECREF(kw);
        return json_pack("{s:i, s:s}",
            "result", -1,
            "comment", "Authz gclass not found"
        );
    }

    return gobj_authenticate(gobj, kw, src);
}
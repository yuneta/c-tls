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
PRIVATE int add_user_login(hgobj gobj, const char *username, json_t *jwt_payload);

PRIVATE json_t *identify_system_user(
    hgobj gobj,
    const char **username,
    BOOL include_groups,
    BOOL verbose
);

PRIVATE json_t *get_user_roles(
    hgobj gobj,
    const char *dst_realm_id,
    const char *dst_service,
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
PRIVATE json_t *cmd_user_roles(hgobj gobj, const char *cmd, json_t *kw, hgobj src);
PRIVATE json_t *cmd_user_authzs(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

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
PRIVATE sdata_desc_t pm_user_roles[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "username",     0,              0,          "Username"),
SDATA_END()
};
PRIVATE sdata_desc_t pm_user_authzs[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "username",     0,              0,          "Username"),
SDATA_END()
};

PRIVATE const char *a_help[] = {"h", "?", 0};

PRIVATE sdata_desc_t command_table[] = {
/*-CMD---type-----------name----------------alias---------------items-----------json_fn---------description---------- */
SDATACM (ASN_SCHEMA,    "help",             a_help,             pm_help,        cmd_help,       "Command's help"),
SDATACM (ASN_SCHEMA,    "authzs",           0,                  pm_authzs,      cmd_authzs,     "Authorization's help"),
SDATACM (ASN_SCHEMA,    "user-roles",       0,                  pm_user_roles,  cmd_user_roles,     "Get roles of user"),
SDATACM (ASN_SCHEMA,    "user-authzs",      0,                  pm_user_authzs, cmd_user_authzs,     "Get permissions of user"),
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

/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    int32_t max_sessions_per_user;

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

    /*---------------------------*
     *      Oauth
     *---------------------------*/
    #define MY_CACHE_OPTIONS "options=max_entries%3D10"

    int level = 0;
    if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
        level = OAUTH2_LOG_TRACE2;
    } else {
        level = OAUTH2_LOG_WARN;
    }
    priv->oath2_sink = oauth2_log_sink_create(
        level,                  // oauth2_log_level_t level,
        oauth2_log_callback,    // oauth2_log_function_t callback,
        gobj                    // void *ctx
    );
    priv->oath2_log = oauth2_log_init(level, priv->oath2_sink);

    const char *pubkey = gobj_read_str_attr(gobj, "jwt_public_key");
    if(pubkey) {
        const char *rv = oauth2_cfg_token_verify_add_options(
            priv->oath2_log,
            &priv->verify,
            "pubkey",
            pubkey,
            "verify.exp=required&expiry=300&verify.iat.slack_before=300"
        );
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
    char path[PATH_MAX];
    yuneta_realm_store_dir(
        path,
        sizeof(path),
        gobj_yuno_role(),
        gobj_yuno_realm_owner(),
        gobj_yuno_realm_id(),
        "authzs",
        TRUE
    );

    json_t *kw_tranger = json_pack("{s:s, s:s, s:b, s:i}",
        "path", path,
        "filename_mask", "%Y",
        "master", 1,
        "on_critical_error", (int)(LOG_OPT_EXIT_ZERO)
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
    const char *treedb_name = "treedb_authzs"; // HACK hardcoded service name
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
     *  HACK pipe inheritance
     */
    gobj_set_bottom_gobj(priv->gobj_treedb, priv->gobj_tranger);
    gobj_set_bottom_gobj(gobj, priv->gobj_treedb);

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
    SET_PRIV(max_sessions_per_user, gobj_read_int32_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    IF_EQ_SET_PRIV(max_sessions_per_user,           gobj_read_int32_attr)
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

    if(!gobj_is_running(priv->gobj_treedb)) {
        gobj_start(priv->gobj_treedb);
    }

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
                json_t *kw_update_node = json_pack("{s:s, s:O, s:{s:b, s:b}}",
                    "topic_name", topic_name,
                    "record", record,
                    "options",
                        "create", 1,
                        "autolink", 1
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

    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    gobj_stop(priv->gobj_treedb);
    gobj_stop(priv->gobj_tranger);

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

    /*-----------------------------*
     *  Get destination service
     *-----------------------------*/
    const char *dst_service = kw_get_str(
        kw,
        "__md_iev__`ievent_gate_stack`0`dst_service",
        "",
        KW_REQUIRED
    );
    if(!gobj_find_service(dst_service, FALSE)) {
        KW_DECREF(kw);
        return json_pack("{s:i, s:s, s:s}",
            "result", -1,
            "comment", "Destination service not found",
            "service", dst_service
        );
    }

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

        json_t *user = identify_system_user(gobj, &username, TRUE, FALSE);
        if(!user) {
            KW_DECREF(kw);
            return json_pack("{s:i, s:s, s:s}",
                "result", -1,
                "comment", "System user not found or not authorized",
                "username", username
            );
        }
        json_decref(user);

        char *comment = "";
        do {
            if(is_ip_allowed(peername)) {
                /*
                 *  IP autorizada sin user/passw, usa logged user
                 */
                comment = "Registered Ip allowed";
                break;
            }

            const char *localhost = "127.0.0.";
            if(strncmp(peername, localhost, strlen(localhost))!=0) {
                /*
                 *  Only localhost is allowed without jwt
                 */
                KW_DECREF(kw);
                return json_pack("{s:i, s:s}",
                    "result", -1,
                    "comment", "Without JWT only localhost is allowed"
                );
            }
            comment = "Local Ip allowed";
        } while(0);

        json_t *services_roles = get_user_roles(
            gobj,
            gobj_yuno_realm_id(),
            dst_service,
            username,
            kw
        );

        if(!kw_has_key(services_roles, dst_service)) {
            KW_DECREF(kw);
            return json_pack("{s:i, s:s, s:s, s:s}",
                "result", -1,
                "comment", "Username has not authz in service",
                "dst_service", dst_service,
                "username", username
            );
        }

        /*
         *  Autorizado
         */
        KW_DECREF(kw);
        return json_pack("{s:i, s:s, s:s, s:s, s:o}",
            "result", 0,
            "comment", comment,
            "username", username,
            "dst_service", dst_service,
            "services_roles", services_roles
        );
    }

    /*-------------------------------*
     *      HERE with user JWT
     *-------------------------------*/
    json_t *jwt_payload = NULL;
    if(!oauth2_token_verify(priv->oath2_log, NULL, priv->verify, jwt, &jwt_payload)) {
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
    if(!strchr(username, '@')) {
        JSON_DECREF(jwt_payload);
        KW_DECREF(kw);
        return json_pack("{s:i, s:s, s:s}",
            "result", -1,
            "comment", "Username must be an email address",
            "username", username
        );
    }
    json_t *user = gobj_get_node(
        priv->gobj_treedb,
        "users",
        json_pack("{s:s, s:b}",
            "id", username,
            "disabled", 0
        ),
        json_pack("{s:b}",
            "with_metadata", 1
        ),
        gobj
    );
    if(!user) {
        json_t *jn_msg = json_pack("{s:i, s:s, s:s}",
            "result", -1,
            "comment", "User not authorized",
            "username", username
        );
        JSON_DECREF(jwt_payload);
        KW_DECREF(kw);
        return jn_msg;
    }

    /*------------------------------------------------*
     *  HACK guarda jwt_payload en src (IEvent_srv)
     *------------------------------------------------*/
    gobj_write_json_attr(src, "jwt_payload", jwt_payload);
    gobj_write_str_attr(src, "__username__", username);

    /*------------------------------*
     *      Save user access
     *------------------------------*/
    add_user_login(gobj, username, jwt_payload);

    /*--------------------------------------------*
     *  Get sessions, check max sessions allowed
     *--------------------------------------------*/
    json_t *sessions = kw_get_dict(user, "__sessions", 0, KW_REQUIRED);
    if(!sessions) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "__sessions NULL",
            NULL
        );
    }
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

    /*------------------------------*
     *      Get user roles
     *------------------------------*/
    json_t *services_roles = get_user_roles(
        gobj,
        gobj_yuno_realm_id(),
        dst_service,
        username,
        kw
    );
    if(!kw_has_key(services_roles, dst_service)) {
        /*
         *  No Autorizado
         */
        json_decref(services_roles);
        JSON_DECREF(user);
        JSON_DECREF(jwt_payload);
        KW_DECREF(kw);
        return json_pack("{s:i, s:s, s:s, s:s}",
            "result", -1,
            "comment", "Username has not authz in service",
            "dst_service", dst_service,
            "username", username
        );
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

    /*--------------------------------*
     *      Autorizado, informa
     *--------------------------------*/
    json_t *jn_resp = json_pack("{s:i, s:s, s:s, s:s, s:o}",
        "result", 0,
        "comment", "JWT User authenticated",
        "username", username,
        "dst_service", dst_service,
        "services_roles", services_roles
    );

    JSON_DECREF(user);
    JSON_DECREF(jwt_payload);
    KW_DECREF(kw);

    return jn_resp;
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

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_user_roles(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *username = kw_get_str(kw, "username", "", 0);

    if(empty_string(username)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_local_sprintf("What username?"),
            0,
            0,
            kw  // owned
        );
    }

    return gobj_build_authzs_doc(gobj, cmd, kw, src);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *cmd_user_authzs(hgobj gobj, const char *cmd, json_t *kw, hgobj src)
{
    const char *username = kw_get_str(kw, "username", "", 0);

    if(empty_string(username)) {
        return msg_iev_build_webix(
            gobj,
            -1,
            json_local_sprintf("What username?"),
            0,
            0,
            kw  // owned
        );
    }

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
        log_fn = 0;
    }

    if(log_fn) {
        log_fn(0,
            "gobj",             "%s", gobj_full_name(gobj),
            "function",         "%s", function,
            "msgset",           "%s", msgset,
            "msg",              "%s", msg,
            NULL
        );
    } else {
        trace_msg(msg);
    }
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *identify_system_user(
    hgobj gobj,
    const char **username,
    BOOL include_groups,
    BOOL verbose
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *user = gobj_get_node(
        priv->gobj_treedb,
        "users",
        json_pack("{s:s, s:b}",
            "id", *username,
            "disabled", 0
        ),
        json_pack("{s:b}",
            "with_metadata", 1
        ),
        gobj
    );
    if(user) {
        return user;
    }

    if(include_groups) {
        /*-------------------------------*
         *  HACK user's group is valid
         *-------------------------------*/
        static gid_t groups[30]; // HACK to use outside
        int ngroups = sizeof(groups)/sizeof(groups[0]);

        getgrouplist(*username, 0, groups, &ngroups);
        for(int i=0; i<ngroups; i++) {
            struct group *gr = getgrgid(groups[i]);
            if(gr) {
                user = gobj_get_node(
                    priv->gobj_treedb,
                    "users",
                    json_pack("{s:s}", "id", gr->gr_name),
                    json_pack("{s:b}",
                        "with_metadata", 1
                    ),
                    gobj
                );
                if(user) {
                    log_warning(0,
                        "gobj",         "%s", gobj_full_name(gobj),
                        "function",     "%s", __FUNCTION__,
                        "msgset",       "%s", MSGSET_INFO,
                        "msg",          "%s", "Using groupname instead of username",
                        "username",     "%s", *username,
                        "groupname",    "%s", gr->gr_name,
                        NULL
                    );
                    *username = gr->gr_name;
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
            "username",     "%s", *username,
            NULL
        );
    }
    return 0; // username as user or group not found
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *append_role(
    hgobj gobj,
    json_t *services_roles, // not owned
    json_t *role,       // not owned
    const char *dst_realm_id,
    const char *dst_service
)
{
    BOOL disabled = kw_get_bool(role, "disabled", 0, KW_REQUIRED|KW_WILD_NUMBER);
    if(!disabled) {
        const char *service = kw_get_str(role, "service", "", KW_REQUIRED);
        const char *realm_id = kw_get_str(role, "realm_id", "", KW_REQUIRED);
        if((strcmp(realm_id, dst_realm_id)==0 || strcmp(realm_id, "*")==0)) {
            if(strcmp(service, dst_service)==0 || strcmp(service, "*")==0
            ) {
                json_t *srv_roles = kw_get_list(
                    services_roles,
                    dst_service,
                    json_array(),
                    KW_CREATE
                );
                json_array_append_new(
                    srv_roles,
                    json_string(kw_get_str(role, "id", "", KW_REQUIRED))
                );
            }
        }
    }

    return services_roles;
}

/***************************************************************************
 *
    Ejemplo de respuesta:

    "services_roles": {
        "treedb_controlcenter": [
            "manage-controlcenter",
            "owner"
        ],
        "treedb_authzs": [
            "manage-authzs",
            "write-authzs",
            "read-authzs",
            "owner"
        ]
    }

 ***************************************************************************/
PRIVATE json_t *get_user_roles(
    hgobj gobj,
    const char *dst_realm_id,
    const char *dst_service,
    const char *username,
    json_t *kw // not owned
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *services_roles = json_object();

    json_t *roles_refs = gobj_node_parents(
        priv->gobj_treedb,
        "users", // topic_name
        json_pack("{s:s}",
            "id", username
        ),
        "roles", // link
        json_pack("{s:b}",
            "list_dict", 1,
            "with_metadata", 1
        ),
        gobj
    );
    if(!roles_refs) {
        return services_roles;
    }

    json_t *required_services = kw_get_list(kw, "required_services", 0, 0);

    int idx; json_t *role_ref;
    json_array_foreach(roles_refs, idx, role_ref) {
        json_t *role = gobj_get_node(
            priv->gobj_treedb,
            "roles", // topic_name
            json_incref(role_ref),
            json_pack("{s:b}",
                "list_dict", 1,
                "with_metadata", 1
            ),
            gobj
        );
        if(kw_get_bool(role, "disabled", 0, KW_REQUIRED|KW_WILD_NUMBER)) {
            json_decref(role);
            continue;
        }

        append_role(
            gobj,
            services_roles,
            role,
            dst_realm_id,
            dst_service
        );

        int idx2; json_t *required_service;
        json_array_foreach(required_services, idx2, required_service) {
            const char *service = json_string_value(required_service);
            if(service) {
                append_role(
                    gobj,
                    services_roles,
                    role,
                    dst_realm_id,
                    service
                );
            }
        }

        json_t *tree_roles = gobj_node_childs(
            priv->gobj_treedb,
            "roles", // topic_name
            json_incref(role),    // 'id' and pkey2s fields are used to find the node
            "roles",
            json_pack("{s:b}", // filter to childs tree
                "disabled", 0
            ),
            json_pack("{s:b, s:b, s:b}",
                "list_dict", 1,
                "with_metadata", 1,
                "recursive", 1
            ),
            gobj
        );
        json_decref(role);

        json_t *child;
        int idx3;
        json_array_foreach(tree_roles, idx3, child) {
            append_role(
                gobj,
                services_roles,
                child,
                dst_realm_id,
                dst_service
            );
            int idx4;
            json_array_foreach(required_services, idx4, required_service) {
                const char *service = json_string_value(required_service);
                if(service) {
                    append_role(
                        gobj,
                        services_roles,
                        child,
                        dst_realm_id,
                        service
                    );
                }
            }
        }
        json_decref(tree_roles);
    }
    json_decref(roles_refs);

    return services_roles;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *append_permission(
    hgobj gobj,
    json_t *services_roles, // not owned
    json_t *role,       // not owned
    const char *dst_realm_id,
    const char *dst_service
)
{
    BOOL disabled = kw_get_bool(role, "disabled", 0, KW_REQUIRED|KW_WILD_NUMBER);
    if(!disabled) {
        const char *service = kw_get_str(role, "service", "", KW_REQUIRED);
        const char *realm_id = kw_get_str(role, "realm_id", "", KW_REQUIRED);
        if((strcmp(realm_id, dst_realm_id)==0 || strcmp(realm_id, "*")==0)) {
            if(strcmp(service, dst_service)==0 || strcmp(service, "*")==0
            ) {
                const char *permission = kw_get_str(role, "permission", "", KW_REQUIRED);
                BOOL deny = kw_get_bool(role, "deny", false, KW_REQUIRED);
                if(!empty_string(permission)) {
                    json_object_set_new(
                        services_roles,
                        permission,
                        deny?json_false():json_true()
                    );
                }

                json_t *permissions = kw_get_list(role, "permissions", 0, KW_REQUIRED);
                int idx; json_t *jn_permission;
                json_array_foreach(permissions, idx, jn_permission) {
                    permission = kw_get_str(jn_permission, "permission", "", KW_REQUIRED);
                    deny = kw_get_bool(jn_permission, "deny", false, KW_REQUIRED);
                    if(!empty_string(permission)) {
                        json_object_set_new(
                            services_roles,
                            permission,
                            deny?json_false():json_true()
                        );
                    }
                }
            }
        }
    }

    return services_roles;
}

/***************************************************************************
 *
    Ejemplo de respuesta:


 ***************************************************************************/
PRIVATE json_t *get_user_permissions(
    hgobj gobj,
    const char *dst_realm_id,
    const char *dst_service,
    const char *username,
    json_t *kw // not owned
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *services_roles = json_object();

    json_t *roles_refs = gobj_node_parents(
        priv->gobj_treedb,
        "users", // topic_name
        json_pack("{s:s}",
            "id", username
        ),
        "roles", // link
        json_pack("{s:b}",
            "list_dict", 1,
            "with_metadata", 1
        ),
        gobj
    );
    if(!roles_refs) {
        return services_roles;
    }

    json_t *required_services = kw_get_list(kw, "required_services", 0, 0);

    int idx; json_t *role_ref;
    json_array_foreach(roles_refs, idx, role_ref) {
        json_t *role = gobj_get_node(
            priv->gobj_treedb,
            "roles", // topic_name
            json_incref(role_ref),
            json_pack("{s:b}",
                "list_dict", 1,
                "with_metadata", 1
            ),
            gobj
        );
        if(kw_get_bool(role, "disabled", 0, KW_REQUIRED|KW_WILD_NUMBER)) {
            json_decref(role);
            continue;
        }

        append_permission(
            gobj,
            services_roles,
            role,
            dst_realm_id,
            dst_service
        );

        int idx2; json_t *required_service;
        json_array_foreach(required_services, idx2, required_service) {
            const char *service = json_string_value(required_service);
            if(service) {
                append_role(
                    gobj,
                    services_roles,
                    role,
                    dst_realm_id,
                    service
                );
            }
        }

        json_t *tree_roles = gobj_node_childs(
            priv->gobj_treedb,
            "roles", // topic_name
            json_incref(role),    // 'id' and pkey2s fields are used to find the node
            "roles",
            json_pack("{s:b}", // filter to childs tree
                "disabled", 0
            ),
            json_pack("{s:b, s:b, s:b}",
                "list_dict", 1,
                "with_metadata", 1,
                "recursive", 1
            ),
            gobj
        );
        json_decref(role);

        json_t *child;
        int idx3;
        json_array_foreach(tree_roles, idx3, child) {
            append_permission(
                gobj,
                services_roles,
                child,
                dst_realm_id,
                dst_service
            );
            int idx4;
            json_array_foreach(required_services, idx4, required_service) {
                const char *service = json_string_value(required_service);
                if(service) {
                    append_permission(
                        gobj,
                        services_roles,
                        child,
                        dst_realm_id,
                        service
                    );
                }
            }
        }
        json_decref(tree_roles);
    }
    json_decref(roles_refs);

    return services_roles;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int add_user_login(hgobj gobj, const char *username, json_t *jwt_payload)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*
     *  Crea user en users_accesses
     */
    json_t *user = json_pack("{s:s, s:s, s:I, s:O}",
        "ev", "login",
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

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int add_user_logout(hgobj gobj, const char *username)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    /*
     *  Crea user en users_accesses
     */
    json_t *user = json_pack("{s:s, s:s, s:I}",
        "ev", "logout",
        "username", username,
        "tm", (json_int_t)time_in_seconds()
    );

    trmsg_add_instance(
        priv->tranger,
        "users_accesses",
        user, // owned
        0,
        0
    );

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

        json_t *user = gobj_get_node(
            priv->gobj_treedb,
            "users",
            json_pack("{s:s}", "id", username),
            json_pack("{s:b}",
                "with_metadata", 1
            ),
            gobj
        );
        if(!user) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "What fuck! user not found",
                "username",     "%s", username,
                NULL
            );
        } else {
            json_t *sessions = kw_get_dict(user, "__sessions", 0, KW_REQUIRED);
            json_t *session = kw_get_dict(sessions, session_id, 0, KW_EXTRACT); // Remove session
            JSON_DECREF(session);

            add_user_logout(gobj, username);
            json_decref(user);
        }
    }

    gobj_unsubscribe_event(src, "EV_ON_CLOSE", 0, gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = { // HACK System gclass, not public events
    // top input
    // bottom input
    {"EV_ON_CLOSE",     0,  0,  ""},
    // internal
    {NULL, 0, 0, ""}
};
PRIVATE const EVENT output_events[] = { // HACK System gclass, not public events
    {NULL, 0, 0, ""}
};
PRIVATE const char *state_names[] = {
    "ST_IDLE",
    NULL
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_ON_CLOSE",             ac_on_close,            0},
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
         *  If the service is not found then deny all.
         */
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "No gclass authz found",
            NULL
        );
        KW_DECREF(kw);
        return FALSE;
    }

    const char *__username__ = kw_get_str(kw, "__temp__`__username__", 0, 0);
    if(!__username__) {
        __username__ = gobj_read_str_attr(src, "__username__");
        if(empty_string(__username__)) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "No __username__ in src",
                "src",          "%s", gobj_full_name(src),
                NULL
            );
            KW_DECREF(kw);
            return FALSE;
        }
    }

    json_t *jn_authz_desc = gobj_authz(gobj_to_check, authz);
    if(!jn_authz_desc) {
        // Error already logged
        KW_DECREF(kw);
        return FALSE;
    }

    json_t *user_authzs = get_user_permissions(
        gobj,
        gobj_yuno_realm_id(),       // dst_realm_id
        gobj_name(gobj_to_check),   // dst_service
        __username__,
        kw // not owned
    );

    BOOL allow = FALSE;
    const char *authz_; json_t *jn_allow;
    json_object_foreach(user_authzs, authz_, jn_allow) {
        if(strcmp(authz_, "*")==0 || strcmp(authz_, authz)==0) {
            allow = json_boolean_value(jn_allow)?1:0;
            break;
        }
    }

    if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
        log_debug_json(0, user_authzs, "user '%s', authz '%s', allow -> %s",
            __username__,
            authz,
            allow?"YES":"NO"
        );
    }

    JSON_DECREF(user_authzs);
    JSON_DECREF(jn_authz_desc);
    KW_DECREF(kw);
    return allow;
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

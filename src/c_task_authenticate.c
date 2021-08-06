/***********************************************************************
 *          C_TASK_AUTHENTICATE.C
 *          Task_authenticate GClass.
 *
 *          Task to authenticate with OAuth2

 *          Copyright (c) 2021 Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <string.h>
#include <stdio.h>
#include "c_task_authenticate.h"

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
PRIVATE json_t *cmd_help(hgobj gobj, const char *cmd, json_t *kw, hgobj src);

PRIVATE sdata_desc_t pm_help[] = {
/*-PM----type-----------name------------flag------------default-----description---------- */
SDATAPM (ASN_OCTET_STR, "cmd",          0,              0,          "command about you want help."),
SDATAPM (ASN_UNSIGNED,  "level",        0,              0,          "command search level in childs"),
SDATA_END()
};

PRIVATE const char *a_help[] = {"h", "?", 0};

PRIVATE sdata_desc_t command_table[] = {
/*-CMD---type-----------name----------------alias-------items-----------json_fn---------description---------- */
SDATACM (ASN_SCHEMA,    "help",             a_help,     pm_help,        cmd_help,       "Command's help"),
SDATA_END()
};


/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------flag------------default---------description---------- */
SDATA (ASN_BOOLEAN,     "offline_access",   0,              1,              "Get offline token"),
SDATA (ASN_OCTET_STR,   "token_endpoint",   0,              "",             "OAuth2 Token EndPoint (interactive jwt)"),
SDATA (ASN_OCTET_STR,   "user_id",          0,              "",             "OAuth2 User Id (interactive jwt)"),
SDATA (ASN_OCTET_STR,   "client_id",        0,              "",             "OAuth2 client id (azp - authorized party ) (interactive jwt)"),
SDATA (ASN_POINTER,     "user_data",        0,              0,              "user data"),
SDATA (ASN_POINTER,     "user_data2",       0,              0,              "more user data"),
SDATA (ASN_POINTER,     "subscriber",       0,              0,              "subscriber of output-events. Not a child gobj."),
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
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    hgobj gobj_http;
} PRIVATE_DATA;




            /******************************
             *      Framework Methods
             ******************************/




/***************************************************************************
 *      Framework Method create
 ***************************************************************************/
PRIVATE void mt_create(hgobj gobj)
{
    //PRIVATE_DATA *priv = gobj_priv_data(gobj);

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
    //SET_PRIV(timeout,               gobj_read_int32_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    //PRIVATE_DATA *priv = gobj_priv_data(gobj);

    //IF_EQ_SET_PRIV(timeout,             gobj_read_int32_attr)
    //END_EQ_SET_PRIV()
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

    /*-----------------------------*
     *      Create http
     *-----------------------------*/
    priv->gobj_http = gobj_create(
        gobj_name(gobj),
        GCLASS_PROT_HTTP_CLI,
        json_pack("{s:I, s:s}",
            "subscriber",
            "url", gobj_read_str_attr(gobj, "token_endpoint")
        ),
        gobj
    );
    // HACK Don't subscribe events, will do the tasks
    gobj_unsubscribe_event(priv->gobj_http, NULL, NULL, gobj);

    gobj_set_bottom_gobj(gobj, priv->gobj_http);

    gobj_set_bottom_gobj(
        priv->gobj_http,
        gobj_create(
            gobj_name(gobj),
            GCLASS_CONNEX,
            json_pack("{s:[s]}", "urls", gobj_read_str_attr(gobj, "token_endpoint")),
            priv->gobj_http
        )
    );

    gobj_start_tree(priv->gobj_http);

    /*-----------------------------*
     *      Create the task
     *-----------------------------*/
    json_t *kw_task = json_pack(
        "{s:I, s:I, s:o, s:["
            "{s:s, s:s}"
            "]}",
        "gobj_jobs", (json_int_t)(size_t)gobj,
        "gobj_results", (json_int_t)(size_t)priv->gobj_http,
        "input_data", json_object(),
        "jobs",
            "exec_action", "action_get_token",
            "exec_result", "result_get_token"
    );

    hgobj gobj_task = gobj_create(gobj_name(gobj), GCLASS_TASK, kw_task, gobj);
    gobj_subscribe_event(gobj_task, "EV_END_TASK", 0, gobj);
    gobj_set_volatil(gobj_task, TRUE); // auto-destroy

    /*-----------------------*
     *      Start task
     *-----------------------*/
    gobj_start(gobj_task);

    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    EXEC_AND_RESET(gobj_stop_tree, priv->gobj_http);

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
             *      Jobs
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *action_get_token(
    hgobj gobj,
    const char *lmethod,
    json_t *kw,
    hgobj src
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    BOOL offline_access = gobj_read_bool_attr(gobj, "offline_access");
    const char *client_id = gobj_read_str_attr(gobj, "client_id");
/*
    headers = CaseInsensitiveDict()
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    data = ""
    form_data = {
        "username": admin_user,
        "password": admin_passw,
        "grant_type": "password",
        "client_id": client_id
    }
    if offline_access:
        form_data["scope"] = "openid offline_access"

    for k in form_data:
        v = form_data[k]
        if not data:
            data += """%s=%s""" % (k,v)
        else:
            data += """&%s=%s""" % (k,v)

    resp = requests.post(url, headers=headers, data=data, verify=False)
    */
    json_t *query = json_pack("{s:o}",
        "query",
        0
    );
    gobj_send_event(priv->gobj_http, "EV_SEND_QUERY", query, gobj);

    KW_DECREF(kw);
    return (void *)0; // continue
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *result_get_token(
    hgobj gobj,
    const char *lmethod,
    json_t *kw,
    hgobj src
)
{
/*
    if resp.status_code != 200:
        print("- '" + repr(cmd) + "': [bright_white on red]Code " + \
            str(resp.status_code) + " " + resp.text + " [/]")
        os._exit(-1)

    r = resp.json()
    access_token = r["access_token"]
    refresh_token = r["refresh_token"]
    if "id_token" in r:
        id_token = r["id_token"]
    else:
        id_token = ""
    expires_in = int(r["expires_in"])
*/

    int result = kw_get_int(kw, "result", -1, KW_REQUIRED);
    if(result == 0 || 1) { // Send ack always
        json_t *input_data = gobj_read_json_attr(src, "input_data");
        json_t *__temp__ = kw_get_dict_value(input_data, "__temp__", 0, KW_REQUIRED|KW_EXTRACT);

        json_t *kw_ack = trq_answer(
            input_data,  // not owned
            0
        );

        if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
            trace_msg("  -> BACK ack rowid %"JSON_INTEGER_FORMAT"",
                kw_get_int(kw_ack, __MD_TRQ__"`__msg_key__", 0, KW_REQUIRED)
            );
        }
//         send_ack(
//             gobj,
//             kw_ack, // owned
//             __temp__ // owned, Set the channel
//         );
    }

    KW_DECREF(kw);
    return (void *)(size_t)result;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *action_logout(
    hgobj gobj,
    const char *lmethod,
    json_t *kw,
    hgobj src
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

/*
        url = keycloak_base_url + "/auth/realms/" + keycloak_realm_name + "/protocol/openid-connect/logout"

        cmd = "Logout ==> POST " + url

        headers = CaseInsensitiveDict()
        headers["Authorization"] = "Bearer " + access_token
        headers["Connection"] = "close"
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        data = ""
        form_data = {
            "refresh_token": refresh_token,
            "client_id": client_id
        }
        for k in form_data:
            v = form_data[k]
            if not data:
                data += """%s=%s""" % (k,v)
            else:
                data += """&%s=%s""" % (k,v)

        resp = requests.post(url, headers=headers, data=data, verify=False)
    */

    KW_DECREF(kw);
    return (void *)0; // continue
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE json_t *result_logout(
    hgobj gobj,
    const char *lmethod,
    json_t *kw,
    hgobj src
)
{
    int result = kw_get_int(kw, "result", -1, KW_REQUIRED);
/*
        if resp.status_code != 204:
            print("- '" + repr(cmd) + "': [bright_white on red]Code " + \
                str(resp.status_code) + " " + resp.text + " [/]")
            os._exit(-1)
*/


    KW_DECREF(kw);
    return (void *)(size_t)result;
}




            /***************************
             *      Local Methods
             ***************************/




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_end_task(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    int result = kw_get_int(kw, "result", -1, KW_REQUIRED);

    if(result < 0) {
    }

    // TODO publish EV_ON_TOKEN

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_stopped(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    // top input
    {"EV_ON_MESSAGE",       0,  0,  0},
    {"EV_END_TASK",         0,  0,  0},
    // bottom input
    {"EV_STOPPED",          0,  0,  ""},
    // internal
    {NULL, 0, 0, ""}
};
PRIVATE const EVENT output_events[] = {
    {"EV_ON_TOKEN",         0,   0,  0},
    {NULL, 0, 0, ""}
};
PRIVATE const char *state_names[] = {
    "ST_IDLE",
    NULL
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_END_TASK",             ac_end_task,            0},
    {"EV_STOPPED",              ac_stopped,             0},
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
    {"action_get_token",            action_get_token,   0},
    {"result_get_token",            result_get_token,   0},
    {"action_logout",               action_logout,      0},
    {"result_logout",               result_logout,      0},
    {0, 0, 0}
};

/*---------------------------------------------*
 *              GClass
 *---------------------------------------------*/
PRIVATE GCLASS _gclass = {
    0,  // base
    GCLASS_TASK_AUTHENTICATE_NAME,
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
        0, //mt_authzs,
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
    0,  //authz_table,
    s_user_trace_level,
    command_table,  // command_table
    0,  // gcflag
};

/***************************************************************************
 *              Public access
 ***************************************************************************/
PUBLIC GCLASS *gclass_task_authenticate(void)
{
    return &_gclass;
}

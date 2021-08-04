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
#define INT4OID         23      // integer
#define TIMESTAMPOID    1114    // timestamp        my time
#define BOOLOID         16      // boolean          my boolean
#define FLOAT4OID       700     // real             my real
#define FLOAT8OID       701     // double precision my double
#define INT8OID         20      // bigint (8 bytes, json_int_t) my integer
#define TEXTOID         25      // text             my string
#define NUMERICOID      1700    // numeric          NaN and infinity values are disallowed
#define JSONOID         114     // json

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/
PRIVATE void on_poll_cb(uv_poll_t *req, int status, int events);
PRIVATE void on_close_cb(uv_handle_t* handle);
PRIVATE int process_result(hgobj gobj, PGresult* result);
PRIVATE int pull_queue(hgobj gobj);

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
/*-CMD---type-----------name----------------alias-------items-----------json_fn---------description---------- */
SDATACM (ASN_SCHEMA,    "help",             a_help,     pm_help,        cmd_help,       "Command's help"),
SDATACM (ASN_SCHEMA,    "authzs",           0,          pm_authzs,      cmd_authzs,     "Authorization's help"),
SDATA_END()
};


/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name----------------------------flag------------default---------description---------- */
SDATA (ASN_JSON,        "schema",                       SDF_RD,         0,              "Database schema"),
SDATA (ASN_OCTET_STR,   "url",                          SDF_PERSIST|SDF_WR,0,           "Url"),
SDATA (ASN_BOOLEAN,     "opened",                       SDF_RD,         0,              "Channel opened (opened is higher level than connected"),
SDATA (ASN_BOOLEAN,     "manual",                       SDF_RD,         0,              "Set true if you want connect manually"),
SDATA (ASN_INTEGER,     "timeout_waiting_connected",    SDF_RD,         10*1000,        ""),
SDATA (ASN_INTEGER,     "timeout_between_connections",  SDF_RD,         5*1000,         "Idle timeout to wait between attempts of connection"),
SDATA (ASN_INTEGER,     "timeout_response",             SDF_WR,         30*000,         "Timeout response"),

SDATA (ASN_POINTER,     "user_data",        0,                          0,              "user data"),
SDATA (ASN_POINTER,     "user_data2",       0,                          0,              "more user data"),
SDATA (ASN_POINTER,     "subscriber",       0,                          0,              "subscriber of output-events. Not a child gobj."),
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
PRIVATE sdata_desc_t authz_table[] = {
/*-AUTHZ-- type---------name------------flag----alias---items---------------description--*/
SDATAAUTHZ (ASN_SCHEMA, "sample",       0,      0,      0,                  "Permission to ..."),
SDATA_END()
};

/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    int32_t timeout_response;
    hgobj timer;

    PGconn *conn;
    uv_poll_t uv_poll;
    int pg_socket;
    BOOL inform_disconnected;

    json_t *dl_queries;
    json_t *cur_query;
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

    priv->timer = gobj_create(gobj_name(gobj), GCLASS_TIMER, 0, gobj);
    priv->dl_queries = json_array();

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
    SET_PRIV(timeout_response,            gobj_read_int32_attr)
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    IF_EQ_SET_PRIV(timeout_response,              gobj_read_int32_attr)
    END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(json_array_size(priv->dl_queries)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "records LOST",
            NULL
        );
        log_debug_json(0, priv->dl_queries, "records LOST");
    }
    JSON_DECREF(priv->dl_queries);
    JSON_DECREF(priv->cur_query);
}

/***************************************************************************
 *      Framework Method start
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    // HACK el start de tcp0 lo hace el timer
    gobj_start(priv->timer);
    if(!gobj_read_bool_attr(gobj, "manual")) {
        set_timeout(priv->timer, 100);
    }
    priv->pg_socket = -1;

    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->conn) {
        PQfinish(priv->conn);
        priv->conn = 0;
        if(priv->pg_socket != -1) {
            uv_poll_stop(&priv->uv_poll);
            uv_close((uv_handle_t*)&priv->uv_poll, on_close_cb);
            priv->pg_socket = -1;
        }
    }
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
PRIVATE void noticeProcessor(void *arg, const char *message)
{
    hgobj gobj = arg;

    if(strstr(message, "NOTICE:")) {
        log_warning(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_DATABASE_ERROR,
            "msg",          "%s", message,
            NULL
        );
    } else {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_DATABASE_ERROR,
            "msg",          "%s", message,
            NULL
        );
    }
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE void set_connected(hgobj gobj)
{
    gobj_send_event(gobj, "EV_CONNECTED", 0, gobj);
}

/***************************************************************************
  *
  ***************************************************************************/
PRIVATE void on_close_cb(uv_handle_t* handle)
{
    hgobj gobj = handle->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_trace_level(gobj) & TRACE_UV) {
        log_debug_printf(0, "<<<< on_close_cb poll p=%p", handle);
    }
    if(priv->conn) {
        PQfinish(priv->conn);
        priv->conn = 0;
    }
    gobj_write_bool_attr(gobj, "opened", FALSE);
    gobj_send_event(gobj, "EV_STOPPED", 0, gobj);
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE void set_disconnected(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->conn) {
        PQfinish(priv->conn);
        priv->conn = 0;
    }
    if(priv->pg_socket != -1) {
        uv_poll_stop(&priv->uv_poll);
        uv_close((uv_handle_t*)&priv->uv_poll, on_close_cb);
        priv->pg_socket = -1;
    }

    set_timeout(priv->timer, 5*1000);
    gobj_change_state(gobj, "ST_WAIT_DISCONNECTED");
    gobj_send_event(gobj, "EV_DISCONNECTED", 0, gobj);
}

/***************************************************************************
 *  on poll callback
 ***************************************************************************/
PRIVATE void on_poll_cb(uv_poll_t *req, int status, int events)
{
    hgobj gobj = req->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_trace_level(gobj) & TRACE_UV) {
        log_debug_printf(0, "<<<< on_poll_cb status %d, events %d, fd %d",
            status, events, priv->pg_socket
        );
    }

    if(status < 0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_LIBUV_ERROR,
            "msg",          "%s", "poll FAILED",
            "uv_error",     "%s", uv_err_name(status),
            NULL
        );
        set_disconnected(gobj);
        return;
    }

    const char *state = gobj_current_state(gobj);
    SWITCHS(state) {
        CASES("ST_CONNECTED")
            if(PQstatus(priv->conn) != CONNECTION_OK) {
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_DATABASE_ERROR,
                    "msg",          "%s", "Task_authenticate connection closed",
                    "error",        "%s", PQerrorMessage(priv->conn),
                    NULL
                );
                set_disconnected(gobj);
                return;
            }
            if(events & UV_READABLE) {
                do {
                    if(PQconsumeInput(priv->conn)) {
                        while(!PQisBusy(priv->conn)) {
                            PGresult* result = PQgetResult(priv->conn);
                            if(result) {
                                // HACK Repeat PQgetResult, must return null
                                // Don't use multiquery or PQsetSingleRowMode
                                if(!PQgetResult(priv->conn)) {
                                    process_result(gobj, result);
                                    PQclear(result);
                                } else {
                                    log_error(0,
                                        "gobj",         "%s", gobj_full_name(gobj),
                                        "function",     "%s", __FUNCTION__,
                                        "msgset",       "%s", MSGSET_DATABASE_ERROR,
                                        "msg",          "%s", "Task_authenticate Multiple Results",
                                        NULL
                                    );
                                }
                                break;
                            }
                        }

                        /*
                         *  After read try to write
                         */
                        int ret = PQflush(priv->conn);
                        if(ret < 0) {
                            set_disconnected(gobj);
                        }
                    } else {
                        log_error(0,
                            "gobj",         "%s", gobj_full_name(gobj),
                            "function",     "%s", __FUNCTION__,
                            "msgset",       "%s", MSGSET_DATABASE_ERROR,
                            "msg",          "%s", "PQconsumeInput FAILED",
                            "error",        "%s", PQerrorMessage(priv->conn),
                            NULL
                        );
                        set_disconnected(gobj);
                        return;
                    }
                } while(0);
            }

            if(events & UV_WRITABLE) {
                int ret = PQflush(priv->conn);
                if(ret < 0) {
                    set_disconnected(gobj);
                } else if(ret == 0) {
                    // No more data to send, put off UV_WRITABLE
                    uv_poll_start(&priv->uv_poll, UV_READABLE, on_poll_cb);
                } else {
                    // == 1 more data to send, continue with UV_WRITABLE
                }
            }

            break;

        CASES("ST_WAIT_CONNECTED")
            Task_authenticatePollingStatusType st = PQconnectPoll(priv->conn);
            if(gobj_trace_level(gobj) & TRACE_UV) {
                log_debug_printf(0, "<<<< ST_WAIT_CONNECTED PQconnectPoll %d", st);
            }
            switch (st) {
            case PGRES_POLLING_OK:
                uv_poll_start(&priv->uv_poll, UV_READABLE|UV_WRITABLE, on_poll_cb);
                set_connected(gobj);
                return;

            case PGRES_POLLING_READING:
                uv_poll_start(&priv->uv_poll, UV_READABLE, on_poll_cb);
                return;
            case PGRES_POLLING_WRITING:
                uv_poll_start(&priv->uv_poll, UV_WRITABLE, on_poll_cb);
                return;
            case PGRES_POLLING_ACTIVE:
                return;
            case PGRES_POLLING_FAILED:
                log_error(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_LIBUV_ERROR,
                    "msg",          "%s", "Task_authenticate connection FAILED",
                    "error",        "%s", PQerrorMessage(priv->conn),
                    NULL
                );
                set_disconnected(gobj);
            }
            break;

        CASES("ST_WAIT_DISCONNECTED")
            Task_authenticatePollingStatusType st = PQconnectPoll(priv->conn);
            if(gobj_trace_level(gobj) & TRACE_UV) {
                log_debug_printf(0, "<<<< ST_WAIT_DISCONNECTED PQconnectPoll %d", st);
            }
            break;

        DEFAULTS
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_PARAMETER_ERROR,
                "msg",          "%s", "state UNKNOWN",
                "state",        "%s", state,
                NULL
            );
            break;
    } SWITCHS_END;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int clear_queue(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_array_clear(priv->dl_queries);
    JSON_DECREF(priv->cur_query);

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int push_queue(
    hgobj gobj,
    json_t *kw // not owned
)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    const char *query = kw_get_str(kw, "query", "", KW_REQUIRED);
    if(empty_string(query)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "query EMPTY",
            NULL
        );
    } else {
        json_array_append(priv->dl_queries, kw);
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int pull_queue(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(PQflush(priv->conn)<0) {
        set_disconnected(gobj);
        return -1;
    }

    if(priv->cur_query) {
        // query in progress
        if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
            trace_msg("cur_query in progress");
        }
        return 0;
    }

    /*
     *  process enqueued data
     */
    if(json_array_size(priv->dl_queries)>0) {
        priv->cur_query = json_incref(json_array_get(priv->dl_queries, 0));
        json_array_remove(priv->dl_queries, 0);
        const char *query = kw_get_str(priv->cur_query, "query", "", KW_REQUIRED);
        if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
            trace_msg("Task_authenticate QUERY ==>\n%s\n", query);
        }
        if(!PQsendQuery(priv->conn, query)) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_DATABASE_ERROR,
                "msg",          "%s", "PQsendQuery FAILED",
                "error",        "%s", PQerrorMessage(priv->conn),
                NULL
            );
        }
        uv_poll_start(&priv->uv_poll, UV_READABLE|UV_WRITABLE, on_poll_cb);
        //set_timeout(priv->timer, priv->timeout_response); falla, no sé porqué
    }

    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int process_result(hgobj gobj, PGresult* result)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    clear_timeout(priv->timer);

    if(!priv->cur_query) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "No query for result",
            NULL
        );
        return 0;
    }

    json_t *kw_result = priv->cur_query;
    priv->cur_query = 0;

    if(!result) {
        char *error = PQerrorMessage(priv->conn);
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_DATABASE_ERROR,
            "msg",          "%s", "Task_authenticate connection closed",
            "error",        "%s", error,
            NULL
        );
        json_object_set_new(kw_result, "result", json_integer(-1));
        json_object_set_new(kw_result, "error", json_string(error));
        if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
            log_debug_json(0, kw_result, "<== Task_authenticate RESULT");
        }
        gobj_publish_event(gobj, "EV_ON_MESSAGE", kw_result);
        return 0;
    }

    ExecStatusType st = PQresultStatus(result);
    BOOL with_binaries = PQbinaryTuples(result);
    if(with_binaries) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "Task_authenticate Binary response NOT SUPPORTED",
            NULL
        );
    }

    switch(st) {
        case PGRES_TUPLES_OK:
        case PGRES_SINGLE_TUPLE:
            json_object_set_new(kw_result, "result", json_integer(0));
            int rows = PQntuples(result);
            int cols = PQnfields(result);
            json_object_set_new(kw_result, "rows", json_integer(rows));
            json_object_set_new(kw_result, "cols", json_integer(cols));
            json_t *jn_data = json_array();
            json_object_set_new(kw_result, "data", jn_data);
            for(int r=0; r<rows; r++) {
                json_t *row = json_object();
                json_array_append_new(jn_data, row);
                for(int c=0; c<cols; c++) {
                    char *col_name = PQfname(result, c);
                    //int format = PQfformat(result, c);

                    char *v = PQgetvalue(result, r, c);
                    if(empty_string(v)) {
                        if(PQgetisnull(result, r, c)) {
                            v = 0;
                        }
                    }
                    if(!v) {
                        json_object_set_new(row, col_name, json_null());
                    } else {
                        Oid oid = PQftype(result, c);
                        switch(oid) {
                            case INT4OID:       // integer
                                json_object_set_new(row, col_name, json_integer(atoi(v)));
                                break;
                            case INT8OID:       // bigint
                                json_object_set_new(row, col_name, json_integer(atol(v)));
                                break;
                            case TIMESTAMPOID:  // timestamp
                                // TODO conver to time_t
                                json_object_set_new(row, col_name, json_string(v));
                                break;
                            case BOOLOID:       // boolean
                                if(strcmp(v, "t")==0) {
                                    json_object_set_new(row, col_name, json_true());
                                } else {
                                    json_object_set_new(row, col_name, json_false());
                                }
                                break;
                            case FLOAT4OID:     // real
                                json_object_set_new(row, col_name, json_real(atof(v)));
                                break;
                            case FLOAT8OID:     // double precision
                                json_object_set_new(row, col_name, json_real(atof(v)));
                                break;
                            case TEXTOID:       // text
                                json_object_set_new(row, col_name, json_string(v));
                                break;
                            default:
                                json_object_set_new(row, col_name, json_string(v));
                                log_error(0,
                                    "gobj",         "%s", gobj_full_name(gobj),
                                    "function",     "%s", __FUNCTION__,
                                    "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                                    "msg",          "%s", "Task_authenticate type NOT IMPLEMENTED",
                                    "oid",          "%d", oid,
                                    NULL
                                );
                                break;

                        }
                    }
                }
            }
            break;

        case PGRES_COMMAND_OK:
            json_object_set_new(kw_result, "result", json_integer(0));
            json_object_set_new(kw_result, "status", json_string(PQcmdStatus(result)));
            json_object_set_new(kw_result, "rows", json_integer(atoi(PQcmdTuples(result))));
            break;

        case PGRES_BAD_RESPONSE: /* an unexpected response was recv'd from the backend */
        case PGRES_NONFATAL_ERROR: /* notice or warning message */
        case PGRES_FATAL_ERROR: /* query failed */
            json_object_set_new(kw_result, "result", json_integer(-1));
            json_object_set_new(kw_result, "error", json_string(PQresultErrorMessage(result)));
            break;

        default:
            json_object_set_new(kw_result, "result", json_integer(-1));
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "No result status supported",
                "st",           "%d", st,
                "status",       "%s", PQresStatus(st),
                NULL
            );
            break;
    }

    if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
        log_debug_json(0, kw_result, "<== Task_authenticate RESULT");
    }

    gobj_publish_event(gobj, "EV_ON_MESSAGE", kw_result);

    return 0;
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

    const char *url = gobj_read_str_attr(gobj, "url");
    if(empty_string(url)) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "Not task_authenticate URI has been configured!",
            NULL
        );
    }
    if(priv->conn) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "PGConn ALREADY set",
            NULL
        );
        PQfinish(priv->conn);
        priv->conn = 0;
    }
    priv->conn = PQconnectStart(url);
    if(priv->conn == NULL) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "PQconnectStart FAILED",
            NULL
        );
    }

    PQsetnonblocking(priv->conn, 1);
    priv->pg_socket = PQsocket(priv->conn);
    uv_poll_init(yuno_uv_event_loop(), &priv->uv_poll, priv->pg_socket);
    priv->uv_poll.data = gobj;

    PQsetNoticeProcessor(priv->conn, noticeProcessor, gobj);

    uv_poll_start(&priv->uv_poll, UV_WRITABLE, on_poll_cb);

    set_timeout(priv->timer, gobj_read_int32_attr(gobj, "timeout_waiting_connected"));

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout_disconnected(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    if (gobj_read_bool_attr(gobj, "manual")) {
        return 0;
    }

    gobj_send_event(gobj, "EV_CONNECT", 0, gobj);

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
        set_timeout(
            priv->timer,
            gobj_read_int32_attr(gobj, "timeout_between_connections")
        );
    }

    if(priv->inform_disconnected) {
        gobj_publish_event(gobj, "EV_ON_CLOSE", 0);
    }
    priv->inform_disconnected = FALSE;

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout_wait_connected(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

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

    gobj_write_bool_attr(gobj, "opened", TRUE);
    priv->inform_disconnected = TRUE;
    gobj_publish_event(gobj, "EV_ON_OPEN", 0);

    pull_queue(gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_timeout_data(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    json_t *kw_result = priv->cur_query;
    priv->cur_query = 0;

    log_error(0,
        "gobj",         "%s", gobj_full_name(gobj),
        "function",     "%s", __FUNCTION__,
        "msgset",       "%s", MSGSET_DATABASE_ERROR,
        "msg",          "%s", "Task_authenticate timeout",
        NULL
    );
    json_object_set_new(kw_result, "result", json_integer(-1));
    json_object_set_new(kw_result, "error", json_string("Task_authenticate timeout"));
    if(gobj_trace_level(gobj) & TRACE_MESSAGES) {
        log_debug_json(0, kw_result, "<== Task_authenticate RESULT");
    }
    gobj_publish_event(gobj, "EV_ON_MESSAGE", kw_result);
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
    {
        "query": "..."
    }
 ***************************************************************************/
PRIVATE int ac_send_query(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if (priv->timeout_response > 0) {
        set_timeout(priv->timer, priv->timeout_response);
    }

    push_queue(gobj, kw);
    pull_queue(gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_enqueue_query(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    push_queue(gobj, kw);

    if(gobj_in_this_state(gobj, "ST_DISCONNECTED")) {
        gobj_send_event(gobj, "EV_CONNECT", 0, gobj);
    }
    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_clear_queue(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    clear_queue(gobj);

    KW_DECREF(kw);
    return 0;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_drop(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    set_disconnected(gobj);

    if(gobj_is_running(gobj)) {
        set_timeout(
            priv->timer,
            gobj_read_int32_attr(gobj, "timeout_between_connections")
        );
    }

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
    {"EV_SEND_QUERY",       EVF_PUBLIC_EVENT,  0,  ""},
    {"EV_CLEAR_QUEUE",      EVF_PUBLIC_EVENT,  0,  ""},
    {"EV_CONNECT",          0,  0,  ""},
    {"EV_DROP",             0,  0,  ""},

    // bottom input
    {"EV_CONNECTED",        0,  0,  ""},
    {"EV_DISCONNECTED",     0,  0,  ""},

    {"EV_TIMEOUT",          0,  0,  ""},
    {"EV_STOPPED",          0,  0,  ""},
    // internal
    {NULL, 0, 0, ""}
};
PRIVATE const EVENT output_events[] = {
    {"EV_ON_OPEN",          EVF_PUBLIC_EVENT,   0,  0},
    {"EV_ON_CLOSE",         EVF_PUBLIC_EVENT,   0,  0},
    {"EV_ON_MESSAGE",       EVF_PUBLIC_EVENT,   0,  0},
    {NULL, 0, 0, ""}
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
    {"EV_SEND_QUERY",       ac_enqueue_query,           0},
    {"EV_CLEAR_QUEUE",      ac_clear_queue,             0},
    {"EV_TIMEOUT",          ac_timeout_disconnected,    0},
    {"EV_STOPPED",          ac_stopped,                 0},
    {0,0,0}
};
PRIVATE EV_ACTION ST_WAIT_CONNECTED[] = {
    {"EV_SEND_QUERY",       ac_enqueue_query,           0},
    {"EV_CLEAR_QUEUE",      ac_clear_queue,             0},
    {"EV_CONNECTED",        ac_connected,               "ST_CONNECTED"},
    {"EV_DISCONNECTED",     ac_disconnected,            "ST_DISCONNECTED"},
    {"EV_STOPPED",          ac_stopped,                 "ST_DISCONNECTED"},
    {"EV_TIMEOUT",          ac_timeout_wait_connected,  "ST_DISCONNECTED"},
    {"EV_DROP",             ac_drop,                    "ST_WAIT_DISCONNECTED"},
    {0,0,0}
};
PRIVATE EV_ACTION ST_CONNECTED[] = {
    {"EV_SEND_QUERY",       ac_send_query,              0},
    {"EV_CLEAR_QUEUE",      ac_clear_queue,             0},
    {"EV_DISCONNECTED",     ac_disconnected,            "ST_DISCONNECTED"},
    {"EV_TIMEOUT",          ac_timeout_data,            0},
    {"EV_DROP",             ac_drop,                    "ST_WAIT_DISCONNECTED"},
    {"EV_STOPPED",          ac_stopped,                 0},
    {0,0,0}
};
PRIVATE EV_ACTION ST_WAIT_DISCONNECTED[] = {
    {"EV_DISCONNECTED",     ac_disconnected,            "ST_DISCONNECTED"},
    {"EV_STOPPED",          ac_stopped,                 "ST_DISCONNECTED"},
    {"EV_TIMEOUT",          ac_stopped,                 "ST_DISCONNECTED"},
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
    authz_table,
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

/***********************************************************************
 *          C_TCP_S1.C
 *          Tcp_S1 GClass.
 *
 *          TCP server level 1 (with SSL) mixin-uv
 *
 *          Copyright (c) 2018 Niyamaka.
 *          All Rights Reserved.
 ***********************************************************************/
#include <string.h>
#include "c_tcp_s1.h"

/***************************************************************************
 *              Constants
 ***************************************************************************/

/***************************************************************************
 *              Structures
 ***************************************************************************/

/***************************************************************************
 *              Prototypes
 ***************************************************************************/
PRIVATE void on_close_cb(uv_handle_t* handle);
PRIVATE void on_connection_cb(uv_stream_t *uv_server_socket, int status);


/***************************************************************************
 *          Data: config, public data, private data
 ***************************************************************************/

/*---------------------------------------------*
 *      Attributes - order affect to oid's
 *---------------------------------------------*/
PRIVATE sdata_desc_t tattr_desc[] = {
/*-ATTR-type------------name--------------------flag----------------default---------description---------- */
SDATA (ASN_JSON,        "crypto",                       SDF_RD,         0,              "Crypto config"),
SDATA (ASN_UNSIGNED,    "connxs",               SDF_RD,             0,              "Current connections"),
SDATA (ASN_OCTET_STR,   "url",                  SDF_RD,             0,              "url listening"),
SDATA (ASN_OCTET_STR,   "lHost",                SDF_RD,             0,              "Listening ip, got from url"),
SDATA (ASN_OCTET_STR,   "lPort",                SDF_RD,             0,              "Listening port, got from url"),
SDATA (ASN_OCTET_STR,   "stopped_event_name",   SDF_RD,            "EV_STOPPED",   "Stopped event name"),
SDATA (ASN_BOOLEAN,     "shared",               SDF_RD,             0,              "Share the port"),
SDATA (ASN_BOOLEAN,     "exitOnError",          SDF_RD,             1,              "Exit if Listen failed"),
SDATA (ASN_JSON,        "child_tree_filter",    SDF_RD,             0,              "tree of chids to create on new accept"),

SDATA (ASN_OCTET_STR,   "top_name",             SDF_RD,             0,              "name of filter gobj"),
SDATA (ASN_OCTET_STR,   "top_gclass_name",      SDF_RD,             0,              "The name of a registered gclass to use in creation of the filter gobj"),
SDATA (ASN_POINTER,     "top_parent",           SDF_RD,             0,              "parent of the top filter gobj"),
SDATA (ASN_JSON,        "top_kw",               SDF_RD,             0,              "kw of filter gobj"),
SDATA (ASN_JSON,        "clisrv_kw",            SDF_RD,             0,              "kw of clisrv gobj"),

SDATA (ASN_POINTER,     "user_data",            0,                  0,              "user data"),
SDATA (ASN_POINTER,     "user_data2",           0,                  0,              "more user data"),
SDATA (ASN_POINTER,     "subscriber",           0,                  0,              "subscriber of output-events. Default if null is parent."),
SDATA_END()
};

/*---------------------------------------------*
 *      GClass trace levels
 *---------------------------------------------*/
enum {
    TRACE_LISTEN        = 0x0001,
    TRACE_NOT_ACCEPTED  = 0x0002,
    TRACE_ACCEPTED      = 0x0004,
};
PRIVATE const trace_level_t s_user_trace_level[16] = {
{"listen",          "Trace listen"},
{"not-accepted",    "Trace not accepted connections"},
{"accepted",        "Trace accepted connections"},
{0, 0},
};

/*---------------------------------------------*
 *              Private data
 *---------------------------------------------*/
typedef struct _PRIVATE_DATA {
    uv_tcp_t uv_socket;
    BOOL uv_socket_open;
    const char *url;
    BOOL exitOnError;

    const char *top_name;
    const char *top_gclass_name;
    hgobj top_parent;
    json_t * top_kw;
    json_t * clisrv_kw;

    uint32_t *pconnxs;

    hytls ytls;

    hgobj subscriber;
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

    json_t *jn_crypto = gobj_read_json_attr(gobj, "crypto");
    priv->ytls = ytls_init(jn_crypto, TRUE);

    /*
     *  Do copy of heavy used parameters, for quick access.
     *  HACK The writable attributes must be repeated in mt_writing method.
     */
    SET_PRIV(url, gobj_read_str_attr)
    SET_PRIV(exitOnError, gobj_read_bool_attr)

    SET_PRIV(top_name, gobj_read_str_attr)
    SET_PRIV(top_gclass_name, gobj_read_str_attr)
    SET_PRIV(top_parent, gobj_read_pointer_attr)
    SET_PRIV(top_kw, gobj_read_json_attr)
    SET_PRIV(clisrv_kw, gobj_read_json_attr)

    priv->pconnxs = gobj_danger_attr_ptr(gobj, "connxs");

    priv->subscriber = (hgobj)gobj_read_pointer_attr(gobj, "subscriber");
    if(!priv->subscriber)
        priv->subscriber = gobj_parent(gobj);
}

/***************************************************************************
 *      Framework Method writing
 ***************************************************************************/
PRIVATE void mt_writing(hgobj gobj, const char *path)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    IF_EQ_SET_PRIV(url, gobj_read_str_attr)

    ELIF_EQ_SET_PRIV(top_name, gobj_read_str_attr)
    ELIF_EQ_SET_PRIV(top_gclass_name, gobj_read_str_attr)
    ELIF_EQ_SET_PRIV(top_parent, gobj_read_pointer_attr)
    ELIF_EQ_SET_PRIV(top_kw, gobj_read_json_attr)
    ELIF_EQ_SET_PRIV(clisrv_kw, gobj_read_json_attr)

    ELIF_EQ_SET_PRIV(exitOnError, gobj_read_bool_attr)
    END_EQ_SET_PRIV()
}

/***************************************************************************
 *      Framework Method destroy
 ***************************************************************************/
PRIVATE void mt_destroy(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    EXEC_AND_RESET(ytls_cleanup, priv->ytls);

    if(!gobj_in_this_state(gobj, "ST_STOPPED")) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_LIBUV_ERROR,
            "msg",          "%s", "GObj NOT STOPPED. UV handler ACTIVE!",
            NULL
        );
    }
}

/***************************************************************************
 *      Framework Method start - return nonstart flag
 ***************************************************************************/
PRIVATE int mt_start(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);
    struct addrinfo hints;
    int r;

    if(!priv->url) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
            "msg",          "%s", "URL NULL",
            NULL);
        if(priv->exitOnError) {
            exit(0); //WARNING exit with 0 to stop daemon watcher!
        } else {
            return -1;
        }
    }

    // uv_inet_pton(AF_INET, priv->url, &bind_addr);
    char schema[20], host[120], port[40];
    r = parse_http_url(priv->url, schema, sizeof(schema), host, sizeof(host), port, sizeof(port), FALSE);
    if(r<0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "parse_http_url() FAILED",
            "url",          "%s", priv->url,
            NULL
        );
        if(priv->exitOnError) {
            exit(0); //WARNING exit with 0 to stop daemon watcher!
        } else {
            return -1;
        }
    }
    if(atoi(port) == 0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
            "msg",          "%s", "Cannot Listen on port 0",
            "url",          "%s", priv->url,
            NULL
        );
        if(priv->exitOnError) {
            exit(0); //WARNING exit with 0 to stop daemon watcher!
        } else {
            return -1;
        }
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;
    struct addrinfo *res;

    r = getaddrinfo(
        host,
        port,
        &hints,
        &res
    );
    if(r!=0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_SYSTEM_ERROR,
            "msg",          "%s", "getaddrinfo() FAILED",
            "lHost",        "%s", host,
            "lPort",        "%s", port,
            "errno",        "%d", errno,
            "strerror",     "%s", strerror(errno),
            NULL
        );
        if(priv->exitOnError) {
            exit(0); //WARNING exit with 0 to stop daemon watcher!
        } else {
            return -1;
        }
    }

    if(gobj_trace_level(gobj) & TRACE_UV) {
        log_debug_printf(0, ">>> uv_init tcpS p=%p", &priv->uv_socket);
    }
    uv_tcp_init(yuno_uv_event_loop(), &priv->uv_socket);
    priv->uv_socket.data = gobj;
    priv->uv_socket_open = TRUE;

    if(gobj_read_bool_attr(gobj, "shared")) {
// TODO FALTA CHEQUEAR si el S.O. lo soporta. Como no lo uso todavía, lo quito.
//         int sfd;
//         uv_fileno((const uv_handle_t *) &priv->uv_socket, &sfd);
//         int optval = 1;
//         if(setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval))<0) {
//             log_error(0,
//                 "gobj",         "%s", gobj_full_name(gobj),
//                 "function",     "%s", __FUNCTION__,
//                 "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
//                 "msg",          "%s", "setsockopt() FAILED",
//                 "url",          "%s", priv->url,
//                 "error",        "%d", errno,
//                 "serror",       "%s", strerror(errno),
//                 NULL
//             );
//             if(priv->exitOnError) {
//                 exit(0); //WARNING exit with 0 to stop daemon watcher!
//             } else {
//                 uv_close((uv_handle_t *)&priv->uv_socket, 0);
//                 priv->uv_socket_open = 0;
//                  freeaddrinfo(res);
//                 return -1;
//             }
//         }
    }

    r = uv_tcp_bind(&priv->uv_socket, res->ai_addr, 0);
    freeaddrinfo(res);
    if(r) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
            "msg",          "%s", "uv_tcp_bind FAILED",
            "url",          "%s", priv->url,
            "error",        "%d", r,
            "uv_error",     "%s", uv_err_name(r),
            NULL
        );
        if(priv->exitOnError) {
            exit(0); //WARNING exit with 0 to stop daemon watcher!
        } else {
            uv_close((uv_handle_t *)&priv->uv_socket, 0);
            priv->uv_socket_open = 0;
            return -1;
        }
    }
    uv_tcp_simultaneous_accepts(&priv->uv_socket, 1);
    if(gobj_trace_level(gobj) & TRACE_UV) {
        log_debug_printf(0, ">>> uv_listen tcp p=%p", &priv->uv_socket);
    }
    r = uv_listen((uv_stream_t*)&priv->uv_socket, 128, on_connection_cb);
    if(r) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
            "msg",          "%s", "Listen FAILED",
            "url",          "%s", priv->url,
            "error",        "%d", r,
            "uv_error",     "%s", uv_err_name(r),
            NULL
        );
        if(priv->exitOnError) {
            exit(0); //WARNING exit with 0 to stop watcher!
        } else {
            uv_close((uv_handle_t *)&priv->uv_socket, 0);
            priv->uv_socket_open = 0;
            return -1;
        }
    }
    gobj_write_str_attr(gobj, "lHost", host);
    gobj_write_str_attr(gobj, "lPort", port);

    /*
     *  Info of "listening..."
     */
    if(gobj_trace_level(gobj) & TRACE_LISTEN) {
        log_info(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
            "msg",          "%s", "Listening...",
            "url",          "%s", priv->url,
            "lHost",        "%s", host,
            "lPort",        "%s", port,
            NULL
        );
    }

    gobj_change_state(gobj, "ST_IDLE");

    return 0;
}

/***************************************************************************
 *      Framework Method stop
 ***************************************************************************/
PRIVATE int mt_stop(hgobj gobj)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(priv->uv_socket_open) {
        if(gobj_trace_level(gobj) & TRACE_UV) {
            log_debug_printf(0, ">>> uv_close tcpS p=%p", &priv->uv_socket);
        }
        gobj_change_state(gobj, "ST_WAIT_STOPPED");
        uv_close((uv_handle_t *)&priv->uv_socket, on_close_cb);
        priv->uv_socket_open = 0;
    }

    return 0;
}




            /***************************
             *      Local Methods
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE void on_close_cb(uv_handle_t* handle)
{
    hgobj gobj = handle->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_trace_level(gobj) & TRACE_UV) {
        log_debug_printf(0, "<<< on_close_cb tcp_s0 p=%p",
            &priv->uv_socket
        );
    }
    gobj_change_state(gobj, "ST_STOPPED");

    /*
     *  Only NOW you can destroy this gobj,
     *  when uv has released the handler.
     */
    const char *stopped_event_name = gobj_read_str_attr(
        gobj,
        "stopped_event_name"
    );
    if(!empty_string(stopped_event_name)) {
        gobj_send_event(
            gobj_parent(gobj),
            stopped_event_name ,
            0,
            gobj
        );
    }

}

/***************************************************************************
 *  Not Accept
 ***************************************************************************/
#ifdef NEW_PATCH_TO_LIBUV
int uv_not_accept(uv_stream_t* server) {
  if (server->accepted_fd == -1)
    return -EAGAIN;
  uv__close(server->accepted_fd);
  server->accepted_fd = -1;
  return 0;
}
#endif

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE BOOL match_allowed_urls(
    hgobj gobj,
    const char *remote_addr,
    json_t *jn_urllist)
{
    char r_schema[20], r_host[120], r_port[40];
    int r = parse_http_url(
        remote_addr,
        r_schema,
        sizeof(r_schema),
        r_host,
        sizeof(r_host),
        r_port,
        sizeof(r_port),
        TRUE
    );
    if(r<0) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_PARAMETER_ERROR,
            "msg",          "%s", "parse_http_url() FAILED",
            "url",          "%s", remote_addr,
            "return",       "%d", r,
            NULL
        );
        return FALSE;
    }

    size_t index;
    json_t *value;
    json_array_foreach(jn_urllist, index, value) {
        json_t *jn_url =  value;
        if(!json_is_string(jn_url)) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_PARAMETER_ERROR,
                "msg",          "%s", "list's url MUST BE a json string",
                NULL
            );
            continue;
        }
        const char *url = json_string_value(jn_url);
        char m_schema[20], m_host[120], m_port[40];
        int r = parse_http_url(
            url,
            m_schema,
            sizeof(m_schema),
            m_host,
            sizeof(m_host),
            m_port,
            sizeof(m_port),
            TRUE
        );
        if(r<0) {
            log_error(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "function",     "%s", __FUNCTION__,
                "msgset",       "%s", MSGSET_PARAMETER_ERROR,
                "msg",          "%s", "parse_http_url() FAILED",
                "url",          "%s", url,
                NULL
            );
            continue;
        }

        /*
         *  Check host TODO check wildchard ips
         */
        if(strcmp(r_host, m_host)==0) {
            int _r_port = atoi(r_port);
            int _m_port = atoi(m_port);
            if(!_m_port) {
                return TRUE;
            }
            if(_m_port == _r_port) {
                return TRUE;
            }
        }
    }

    return FALSE;
}

/***************************************************************************
 *
 ***************************************************************************/
PRIVATE BOOL match_denied_urls(
    hgobj gobj,
    const char *remote_addr,
    json_t *jn_urllist)
{
    // TODO
    return FALSE;
}

/***************************************************************************
 *  Accept cb
 ***************************************************************************/
PRIVATE void on_connection_cb(uv_stream_t *uv_server_socket, int status)
{
    hgobj gobj = uv_server_socket->data;
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    if(gobj_trace_level(gobj) & TRACE_UV) {
        log_debug_printf(0, "<<< on_connection_cb p=%p", &priv->uv_socket);
    }

    if (status) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
            "msg",          "%s", "??? FAILED",
            NULL
        );
        return;
    }

    /*--------------------------------------*
     *  statistics
     *--------------------------------------*/
    (*priv->pconnxs)++;

    /*-------------------*
     *  Name of clisrv
     *-------------------*/
    char xname[80];
    snprintf(xname, sizeof(xname), "clisrv-%u",
        *priv->pconnxs
    );

    /*-----------------------------------------------------------*
     *  Create a filter, if.
     *  A filter is a top level gobj tree over the clisrv gobj.
     *-----------------------------------------------------------*/
    hgobj gobj_top = 0;
    hgobj gobj_bottom = 0;

    json_t *jn_child_tree_filter = gobj_read_json_attr(gobj, "child_tree_filter");
    if(json_is_object(jn_child_tree_filter)) {
        /*--------------------------------*
         *      New method
         *--------------------------------*/
        const char *op = kw_get_str(jn_child_tree_filter, "op", "find", 0);
        json_t *jn_filter = kw_get_dict(jn_child_tree_filter, "kw", 0, 0);
        if(1 || strcmp(op, "find")==0) { // here, only find operation is valid.
            JSON_INCREF(jn_filter);
            gobj_top = gobj_find_child(gobj_parent(gobj), jn_filter);
            if(!gobj_top) {
                if(gobj_trace_level(gobj) & TRACE_NOT_ACCEPTED) {
                    log_info(0,
                        "gobj",         "%s", gobj_full_name(gobj),
                        "function",     "%s", __FUNCTION__,
                        "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
                        "msg",          "%s", "Clisrv not accepted: no free child tree found",
                        NULL
                    );
                }
                uv_not_accept((uv_stream_t *)uv_server_socket);
                return;
            } else {
                gobj_bottom = gobj_last_bottom_gobj(gobj_top);
                if(!gobj_bottom) {
                    gobj_bottom = gobj_top;
                }
            }
            if(gobj_trace_level(gobj) & TRACE_ACCEPTED) {
                char tree_name[512];
                gobj_full_bottom_name(gobj_top, tree_name, sizeof(tree_name));
                log_info(0,
                    "gobj",         "%s", gobj_full_name(gobj),
                    "function",     "%s", __FUNCTION__,
                    "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
                    "msg",          "%s", "Clisrv accepted",
                    "tree_name",    "%s", tree_name,
                    NULL
                );
            }
        }
    } else if(!empty_string(priv->top_gclass_name)) {
        /*---------------------------------------------------------*
         *      Old method
         *  Crea la clase top de un arbol implicito (gobj_top)
         *  y luego le pregunta si tiene gobj_botom,
         *  por si ha creado un pipe de objetos.
         *---------------------------------------------------------*/
        GCLASS *gc = gobj_find_gclass(priv->top_gclass_name, TRUE);
        /*
         *  We must create a top level, a gobj filter
         */
        if(!gc) {
            log_info(0,
                "gobj",         "%s", gobj_full_name(gobj),
                "msgset",       "%s", MSGSET_INTERNAL_ERROR,
                "msg",          "%s", "GClass not registered",
                "gclass",       "%s", priv->top_gclass_name,
                NULL
            );
            return;
        }
        if(priv->top_kw) {
            json_incref(priv->top_kw);
        }
        gobj_top = gobj_create_volatil(
            xname,
            gc,
            priv->top_kw,
            priv->top_parent?priv->top_parent:priv->subscriber
        );
        gobj_bottom = gobj_last_bottom_gobj(gobj_top);
        if(!gobj_bottom) {
            gobj_bottom = gobj_top;
        }
        gobj_start(gobj_top);
    }

    if(!gobj_bottom && !priv->subscriber) {
        log_error(0,
            "gobj",         "%s", gobj_full_name(gobj),
            "function",     "%s", __FUNCTION__,
            "msgset",       "%s", MSGSET_INTERNAL_ERROR,
            "msg",          "%s", "Bad tree filter or no subscriber",
            NULL
        );
        uv_not_accept((uv_stream_t *)uv_server_socket);
        return;
    }

    /*----------------------------*
     *  Create the clisrv gobj.
     *----------------------------*/
    json_t *kw_clisrv = priv->clisrv_kw;
    JSON_INCREF(kw_clisrv);
    if(!kw_clisrv) {
        kw_clisrv = json_object();
    }
    json_object_set_new(kw_clisrv, "ytls", json_integer((json_int_t)(size_t)priv->ytls));

    hgobj clisrv = gobj_create_volatil(
        xname, // the same name as the filter, if filter.
        GCLASS_TCP1,
        kw_clisrv,
        gobj_bottom?gobj_bottom:priv->subscriber
    );
    gobj_write_str_attr(
        clisrv,
        "lHost",
        gobj_read_str_attr(gobj, "lHost")
    );
    gobj_write_str_attr(
        clisrv,
        "lPort",
        gobj_read_str_attr(gobj, "lPort")
    );
    gobj_write_bool_attr(
        clisrv,
        "clisrv",
        TRUE
    );

    if(gobj_bottom) {
        if(gobj_has_attr(gobj_bottom, "tcp0")) {
            // Old method previous to bottom gobj (websocket and V2).
            gobj_write_pointer_attr(gobj_bottom, "tcp0", clisrv);
        }
        gobj_set_bottom_gobj(gobj_bottom, clisrv);
    }

    /*
     *  srvsock needs to know of disconnected event
     *  for deleting gobjs or do statistics
     */
    json_t *kw_subs = json_pack("{s:{s:b}}", "__config__", "__hard_subscription__", 1);
    gobj_subscribe_event(clisrv, "EV_STOPPED", kw_subs, gobj);

    gobj_start(clisrv);

    /*--------------------------------------*
     *  All ready: accept the connection
     *  to the new child.
     *--------------------------------------*/
    if (accept_connection1(clisrv, uv_server_socket)!=0) {
        gobj_destroy(clisrv);
        return;
    }

    /*--------------------------------------*
     *  Only when accept the connection
     *  we know the peername.
     *  TODO allowed/denied esto no está bien, revísalo!
     *  Hay que comprobar las allowed/denied al elegir el tree!
     *  Revisa accept_connection
     *--------------------------------------*/
    /*--------------------------------------*
     *  Check allowed url's
     *--------------------------------------*/
    const char *peername = gobj_read_str_attr(clisrv, "peername");
    if(gobj_has_attr(gobj_top, "allowd_urls")) {
        json_t *jn_urllist = gobj_read_json_attr(gobj_top, "allowd_urls");
        if(jn_urllist && json_array_size(jn_urllist)>0) {
            if(!match_allowed_urls(gobj, peername, jn_urllist)) {
                if(gobj_trace_level(gobj) & TRACE_NOT_ACCEPTED) {
                    log_info(0,
                        "gobj",         "%s", gobj_full_name(gobj),
                        "function",     "%s", __FUNCTION__,
                        "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
                        "msg",          "%s", "Clisrv not accepted: Not match allowed url",
                        NULL
                    );
                }
                gobj_stop(clisrv);
                gobj_destroy(clisrv);
                return;
            }
        }
    }
    /*--------------------------------------*
     *  Check denied url's
     *--------------------------------------*/
    if(gobj_has_attr(gobj_top, "denied_urls")) {
        json_t *jn_urllist = gobj_read_json_attr(gobj_top, "denied_urls");
        if(jn_urllist && json_array_size(jn_urllist)>0) {
            if(match_denied_urls(gobj, peername, jn_urllist)) {
                if(gobj_trace_level(gobj) & TRACE_NOT_ACCEPTED) {
                    log_info(0,
                        "gobj",         "%s", gobj_full_name(gobj),
                        "function",     "%s", __FUNCTION__,
                        "msgset",       "%s", MSGSET_CONNECT_DISCONNECT,
                        "msg",          "%s", "Clisrv not accepted: Match denied url",
                        NULL
                    );
                }
                gobj_stop(clisrv);
                gobj_destroy(clisrv);
                return;
            }
        }
    }
}




            /***************************
             *      Actions
             ***************************/




/***************************************************************************
 *
 ***************************************************************************/
PRIVATE int ac_clisrv_stopped(hgobj gobj, const char *event, json_t *kw, hgobj src)
{
    PRIVATE_DATA *priv = gobj_priv_data(gobj);

    (*priv->pconnxs)--;

    JSON_DECREF(kw);
    return 0;
}

/***************************************************************************
 *                          FSM
 ***************************************************************************/
PRIVATE const EVENT input_events[] = {
    {"EV_STOPPED",          0},
    {NULL, 0}
};
PRIVATE const EVENT output_events[] = {
    {NULL, 0}
};
PRIVATE const char *state_names[] = {
    "ST_STOPPED",
    "ST_WAIT_STOPPED",
    "ST_IDLE",          /* H2UV handler for UV */
    NULL
};

PRIVATE EV_ACTION ST_STOPPED[] = {
    {"EV_STOPPED",         ac_clisrv_stopped,       0},
    {0,0,0}
};

PRIVATE EV_ACTION ST_WAIT_STOPPED[] = {
    {"EV_STOPPED",         ac_clisrv_stopped,       0},
    {0,0,0}
};

PRIVATE EV_ACTION ST_IDLE[] = {
    {"EV_STOPPED",         ac_clisrv_stopped,       0},
    {0,0,0}
};

PRIVATE EV_ACTION *states[] = {
    ST_STOPPED,
    ST_WAIT_STOPPED,
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
    GCLASS_TCP_S1_NAME,      // CHANGE WITH each gclass
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
        0, //mt_future24,
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
        0, //mt_snap_nodes,
        0, //mt_set_nodes_snap,
        0, //mt_list_nodes_snaps,
        0, //mt_future52,
        0, //mt_future53,
        0, //mt_future54,
        0, //mt_future55,
        0, //mt_future56,
        0, //mt_future57,
        0, //mt_future58,
        0, //mt_future59,
        0, //mt_future60,
        0, //mt_future61,
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
PUBLIC GCLASS *gclass_tcp_s1(void)
{
    return &_gclass;
}

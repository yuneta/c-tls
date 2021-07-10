/****************************************************************************
 *          C_TCP1.H
 *          Tcp1 GClass.
 *
 *          GClass of TCP level 1 (SSL) mixin-uv
 *
 *          Copyright (c) 2018 by Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#pragma once

#include <yuneta.h>
#include <ytls.h>

#ifdef __cplusplus
extern "C"{
#endif

/***************************************************************
 *              Constants
 ***************************************************************/
#define GCLASS_TCP1_NAME "Tcp1"
#define GCLASS_TCP1 gclass_tcp1()

/***************************************************************
 *              Prototypes
 ***************************************************************/
PUBLIC GCLASS *gclass_tcp1(void);

PUBLIC int accept_connection1(
    hgobj clisvr,
    void *uv_server_socket
);

#ifdef __cplusplus
}
#endif

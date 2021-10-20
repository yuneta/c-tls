/****************************************************************************
 *          C_TCP_S1.H
 *          Tcp_S1 GClass.
 *
 *          TCP server level 1 (with SSL) uv-mixin
 *
 *          Copyright (c) 2018 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#pragma once

#include <yuneta.h>
#include <ytls.h>
#include "c_tcp1.h"


#ifdef __cplusplus
extern "C"{
#endif

/***************************************************************
 *              Constants
 ***************************************************************/
#define GCLASS_TCP_S1_NAME "TcpS1"
#define GCLASS_TCP_S1 gclass_tcp_s1()

/***************************************************************
 *              Prototypes
 ***************************************************************/
PUBLIC GCLASS *gclass_tcp_s1(void);

#ifdef __cplusplus
}
#endif

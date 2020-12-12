/****************************************************************************
 *          C_AUTHZ.H
 *          Authz GClass.
 *
 *          Authorization Manager
 *
 *          Copyright (c) 2020 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#pragma once

#include <yuneta.h>

#ifdef __cplusplus
extern "C"{
#endif

/***************************************************************
 *              Constants
 ***************************************************************/
#define GCLASS_AUTHZ_NAME "Authz"
#define GCLASS_AUTHZ gclass_authz()

/***************************************************************
 *              Prototypes
 ***************************************************************/
PUBLIC GCLASS *gclass_authz(void);

#ifdef __cplusplus
}
#endif

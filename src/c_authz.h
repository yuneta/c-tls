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

PUBLIC BOOL authz_checker(hgobj gobj_to_check, const char *authz, json_t *kw, hgobj src);
PUBLIC json_t *authenticate_parser(hgobj gobj_service, json_t *kw, hgobj src);

#ifdef __cplusplus
}
#endif

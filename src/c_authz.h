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

PUBLIC BOOL authz_checker(hgobj gobj, const char *level, json_t *kw, hgobj src);
PUBLIC int authz_allow(hgobj gobj, const char *user, const char *level, json_t *kw);
PUBLIC int authz_deny(hgobj gobj, const char *user, const char *level, json_t *kw);


#ifdef __cplusplus
}
#endif

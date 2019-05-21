/****************************************************************************
 *          C_CONNEXS.H
 *          Connexs GClass.
 *
 *          Auto-connection and multi-destine over tcp with tls
 *
 *          Copyright (c) 2018 Niyamaka.
 *          All Rights Reserved.
 ****************************************************************************/
#ifndef _C_CONNEXS_H
#define _C_CONNEXS_H 1

#include <yuneta.h>
#include "c_tcp1.h"

#ifdef __cplusplus
extern "C"{
#endif

/***************************************************************
 *              Constants
 ***************************************************************/
#define GCLASS_CONNEXS_NAME "Connexs"
#define GCLASS_CONNEXS gclass_connexs()

/***************************************************************
 *              Prototypes
 ***************************************************************/
PUBLIC GCLASS *gclass_connexs(void);

#ifdef __cplusplus
}
#endif

#endif

/****************************************************************************
 *          C_TASK_AUTHENTICATE.H
 *          Task_authenticate GClass.
 *
 *          Task to authenticate with OAuth2
 *
 *          Copyright (c) 2021 Niyamaka.
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
#define GCLASS_TASK_AUTHENTICATE_NAME "Task_authenticate"
#define GCLASS_TASK_AUTHENTICATE gclass_task_authenticate()

/***************************************************************
 *              Prototypes
 ***************************************************************/
PUBLIC GCLASS *gclass_task_authenticate(void);

#ifdef __cplusplus
}
#endif

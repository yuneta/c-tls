/****************************************************************************
 *              YUNETA_TLS_REGISTER.C
 *              Yuneta
 *
 *              Copyright (c) 2018 Niyamaka.
 *              All Rights Reserved.
 ****************************************************************************/
#include "yuneta_tls.h"
#include "yuneta_tls_register.h"

/***************************************************************************
 *  Data
 ***************************************************************************/

/***************************************************************************
 *  Register internal yuno gclasses and services
 ***************************************************************************/
PUBLIC int yuneta_register_c_tls(void)
{
    static BOOL initialized = FALSE;
    if(initialized) {
        return -1;
    }

    gobj_register_gclass(GCLASS_CONNEXS);

    /*
     *  Mixin uv-gobj
     */
    gobj_register_gclass(GCLASS_TCP1);
    gobj_register_gclass(GCLASS_TCP_S1);
    initialized = TRUE;

    return 0;
}


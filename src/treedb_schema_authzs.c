#pragma once

/*
 *
            ┌───────────────────────────────────────┐
            │               users                   │
            └───────────────────────────────────────┘
                    ▲ n (hook 'users')      1 (fkey 'group_id')
                    │                       │
                    │                       │
                    └───────────────────────┘


*/

static char treedb_schema_authzs[]= "\
{                                                                   \n\
    'id': 'authzs',                                                 \n\
    'schema_version': '1',                                          \n\
    'topics': [                                                     \n\
        {                                                           \n\
            'topic_name': 'users' ,                                 \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'User/Group/Role',                    \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'description': {                                    \n\
                    'header': 'Description',                        \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'permissions': {                                    \n\
                    'header': 'Permissions',                        \n\
                    'fillspace': 10,                                \n\
                    'type': 'list',                                 \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'disabled': {                                       \n\
                    'header': 'Disabled',                           \n\
                    'fillspace': 7,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'system_user': {                                    \n\
                    'header': 'System User',                        \n\
                    'fillspace': 7,                                 \n\
                    'type': 'boolean',                              \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'group_id': {                                       \n\
                    'header': 'group_id',                           \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'fkey'                                      \n\
                    ]                                               \n\
                },                                                  \n\
                'users': {                                          \n\
                    'header': 'users',                              \n\
                    'fillspace': 20,                                \n\
                    'type': 'array',                                \n\
                    'flag': ['hook'],                               \n\
                    'hook': {                                       \n\
                        'users': 'group_id'                         \n\
                    }                                               \n\
                }                                                   \n\
            }                                                       \n\
        }                                                           \n\
    ]                                                               \n\
}                                                                   \n\
";

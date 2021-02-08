#pragma once

/*
 *
    {}  dict hook   (N unique childs)
    []  list hook   (n not-unique childs)
    (↖) 1 fkey      (1 parent)
    [↖] n fkeys     (n parents)
    {↖} N fkeys     (N parents) ???


    * field required
    = field inherited

                        roles
            ┌───────────────────────────┐
            │* id                       │
            │                           │
            │                  roles {} │ ◀─┐N
            │                           │   │
            │        parent_role_id (↖) │ ──┘ 1
            │                           │
            │* description              │
            │= disabled                 │
            │* realm_id                 │
            │* service                  │
            │* permission               │
            │                           │
            │                           │
            │                  users {} │ ◀─┐N
            │                           │   │
            │  _geometry                │   │
            └───────────────────────────┘   │
                                            │
                                            │
                        users               │
            ┌───────────────────────────┐   │
            │* id                       │   │
            │                           │   │
            │                 roles [↖] │ ──┘n
            │                           │
            │= disabled                 │
            │  properties               │
            │                           │
            │  __sessions               │
            │  _geometry                │
            └───────────────────────────┘



*/

static char treedb_schema_authzs[]= "\
{                                                                   \n\
    'id': 'treedb_authzs',                                          \n\
    'schema_version': '5',                                          \n\
    'topics': [                                                     \n\
        {                                                           \n\
            'topic_name': 'roles',                                  \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '3',                                   \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'Role',                               \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'roles': {                                          \n\
                    'header': 'Roles',                              \n\
                    'fillspace': 10,                                \n\
                    'type': 'dict',                                 \n\
                    'flag': ['hook'],                               \n\
                    'hook': {                                       \n\
                        'roles': 'parent_role_id'                   \n\
                    }                                               \n\
                },                                                  \n\
                'parent_role_id': {                                 \n\
                    'header': 'Role Parent',                        \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'fkey'                                      \n\
                    ]                                               \n\
                },                                                  \n\
                'description': {                                    \n\
                    'header': 'Description',                        \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'disabled': {                                       \n\
                    'header': 'Disabled',                           \n\
                    'fillspace': 4,                                 \n\
                    'type': 'boolean',                              \n\
                    'default': false,                               \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent',                               \n\
                        'inherit'                                   \n\
                    ]                                               \n\
                },                                                  \n\
                'realm_id': {                                       \n\
                    'header': 'Realm Id',                           \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'service': {                                        \n\
                    'header': 'Service',                            \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'permission': {                                     \n\
                    'header': 'Permission',                         \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'parameters': {                                     \n\
                    'header': 'Parameters',                         \n\
                    'fillspace': 10,                                \n\
                    'type': 'dict',                                 \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                'users': {                                          \n\
                    'header': 'Users',                              \n\
                    'fillspace': 10,                                \n\
                    'type': 'dict',                                 \n\
                    'flag': ['hook'],                               \n\
                    'hook': {                                       \n\
                        'users': 'roles'                            \n\
                    }                                               \n\
                },                                                  \n\
                '_geometry': {                                      \n\
                    'header': 'Geometry',                           \n\
                    'type': 'blob',                                 \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        },                                                          \n\
        {                                                           \n\
            'topic_name': 'users',                                  \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '5',                                   \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'User',                               \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'roles': {                                          \n\
                    'header': 'Role',                               \n\
                    'fillspace': 10,                                \n\
                    'type': 'array',                                \n\
                    'flag': [                                       \n\
                        'fkey'                                      \n\
                    ]                                               \n\
                },                                                  \n\
                'disabled': {                                       \n\
                    'header': 'Disabled',                           \n\
                    'fillspace': 4,                                 \n\
                    'type': 'boolean',                              \n\
                    'default': false,                               \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent',                               \n\
                        'inherit'                                   \n\
                    ]                                               \n\
                },                                                  \n\
                'properties': {                                     \n\
                    'header': 'Properties',                         \n\
                    'fillspace': 10,                                \n\
                    'type': 'dict',                                 \n\
                    'flag': [                                       \n\
                        'writable',                                 \n\
                        'persistent'                                \n\
                    ]                                               \n\
                },                                                  \n\
                '__sessions': {                                     \n\
                    'header': 'Sessions',                           \n\
                    'fillspace': 10,                                \n\
                    'type': 'dict',                                 \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                '_geometry': {                                      \n\
                    'header': 'Geometry',                           \n\
                    'type': 'blob',                                 \n\
                    'fillspace': 10,                                \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        }                                                           \n\
    ]                                                               \n\
}                                                                   \n\
";

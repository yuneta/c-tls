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
            │                           │
            │                           │
            │         authorizations {} │ ◀─────────┐N
            │                           │           │
            │                  users {} │ ◀─┐N      │
            │                           │   │       │
            └───────────────────────────┘   │       │
                                            │       │
                                            │       │
                        users               │       │
            ┌───────────────────────────┐   │       │
            │* id                       │   │       │
            │                           │   │       │
            │               role_id [↖] │ ──┘n      │
            │                           │           │
            │  properties               │           │
            └───────────────────────────┘           │
                                                    │
                                                    │
                    authorizations                  │
            ┌───────────────────────────┐           │
            │* id                       │           │
            │                           │           │
            │               role_id [↖] │ ──────────┘ n
            │                           │
            │* description              │
            │* service                  │
            │* constraints              │
            └───────────────────────────┘


Ex constraints:

    "user"

    [
        {
            "authz": "__inject_event__",
            "event": ["EV_START_WORKTIME", "EV_STOP_WORKTIME", "EV_END_WORKING_DAY"],
            "allow": true,
            "topic_name": "==fichajes"
            "topic_id": "=={{__username__}}"
        },
        {
            "authz": ["__subscribe_event__"],
            "event": ["EV_END_WORKING_DAY"],
            "allow": true,
            "topic_name": "==fichajes"
            "topic_id": "=={{__username__}}"
        },
        {
            "authz": ["__inject_event__"],
            "event": "EV_LIST_USER_FICHAJES",
            "allow": true,
            "topic_name": "==fichajes"
            "topic_id": "=={{__username__}}"
        }
        {
            "authz": ["__inject_event__"],
            "event": "EV_LIST_VALIDATIONS",
            "allow": true,
            "topic_name": "==validations"
            "topic_id": "=={{__username__}}"
        }
    ]


    "manager"

    [
        {
            "authz": ["__subscribe_event__"],
            "event": ["EV_START_WORKTIME", "EV_STOP_WORKTIME", "EV_END_WORKING_DAY"],
            "allow": true,
            "topic_name": "==fichajes"
            "topic_id": "==departments.{{__username__}}.users"
        },
        {
            "authz": ["__inject_event__"],
            "event": "EV_LIST_USER_FICHAJES",
            "allow": true,
            "topic_name": "==fichajes"
            "topic_id": "==departments.{{__username__}}.users"
        }
        {
            "authz": ["__inject_event__"],
            "event": ["EV_SAVE_VALIDATIONS", "EV_LIST_VALIDATIONS"],
            "allow": true,
            "topic_name": "==validations"
            "topic_id": "==departments.{{__username__}}.users"
        }
    ]

    "admin"

    [
        {
            "authz": [],
            "event": [],
            "allow": true,
            "topic_name": "==.*"
            "topic_id": "==.*"
        }
    ]

*/

static char treedb_schema_authzs[]= "\
{                                                                   \n\
    'id': 'authzs',                                                 \n\
    'schema_version': '1',                                          \n\
    'topics': [                                                     \n\
        {                                                           \n\
            'topic_name': 'roles',                                  \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
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
                        'persistent',                               \n\
                        'inherit'                                   \n\
                    ]                                               \n\
                },                                                  \n\
                'realm_id': {                                       \n\
                    'header': 'Realm Id',                           \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'authorizations': {                                 \n\
                    'header': 'Authorizations',                     \n\
                    'fillspace': 10,                                \n\
                    'type': 'dict',                                 \n\
                    'flag': ['hook'],                               \n\
                    'hook': {                                       \n\
                        'authorizations': 'role_id'                 \n\
                    }                                               \n\
                },                                                  \n\
                'users': {                                          \n\
                    'header': 'Users',                              \n\
                    'fillspace': 10,                                \n\
                    'type': 'dict',                                 \n\
                    'flag': ['hook'],                               \n\
                    'hook': {                                       \n\
                        'users': 'role_id'                          \n\
                    }                                               \n\
                }                                                   \n\
            }                                                       \n\
        },                                                          \n\
        {                                                           \n\
            'topic_name': 'users',                                  \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
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
                'role_id': {                                        \n\
                    'header': 'Role',                               \n\
                    'fillspace': 10,                                \n\
                    'type': 'array',                                \n\
                    'flag': [                                       \n\
                        'fkey'                                      \n\
                    ]                                               \n\
                },                                                  \n\
                '_sessions': {                                      \n\
                    'header': 'Sessions',                           \n\
                    'fillspace': 10,                                \n\
                    'type': 'dict',                                 \n\
                    'flag': [                                       \n\
                    ]                                               \n\
                },                                                  \n\
                'properties': {                                     \n\
                    'header': 'Properties',                         \n\
                    'fillspace': 10,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent'                                \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        },                                                          \n\
        {                                                           \n\
            'topic_name': 'authorizations',                         \n\
            'pkey': 'id',                                           \n\
            'system_flag': 'sf_string_key',                         \n\
            'topic_version': '1',                                   \n\
            'cols': {                                               \n\
                'id': {                                             \n\
                    'header': 'Authorization',                      \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'uuid',                                     \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'role_id': {                                        \n\
                    'header': 'Role',                               \n\
                    'fillspace': 10,                                \n\
                    'type': 'array',                                \n\
                    'flag': [                                       \n\
                        'fkey'                                      \n\
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
                'service': {                                        \n\
                    'header': 'Service',                            \n\
                    'fillspace': 10,                                \n\
                    'type': 'string',                               \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                },                                                  \n\
                'constraints': {                                    \n\
                    'header': 'Constraints',                        \n\
                    'fillspace': 10,                                \n\
                    'type': 'blob',                                 \n\
                    'flag': [                                       \n\
                        'persistent',                               \n\
                        'required'                                  \n\
                    ]                                               \n\
                }                                                   \n\
            }                                                       \n\
        }                                                           \n\
    ]                                                               \n\
}                                                                   \n\
";

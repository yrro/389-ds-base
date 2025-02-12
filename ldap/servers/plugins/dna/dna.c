/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 *
 * License: GPL (version 3 or any later version).
 * See LICENSE for details.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


/**
 * Distributed Numeric Assignment plug-in
 */
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include "portable.h"
#include "nspr.h"
#include "slapi-private.h"
#include "prclist.h"

#include <sys/stat.h>

#define DNA_PLUGIN_SUBSYSTEM "dna-plugin"
#define DNA_PLUGIN_VERSION 0x00020000

#define DNA_DN "cn=Distributed Numeric Assignment Plugin,cn=plugins,cn=config" /* temporary */

#define DNA_SUCCESS SLAPI_PLUGIN_SUCCESS
#define DNA_FAILURE SLAPI_PLUGIN_FAILURE

/* Default range request timeout */
/* use the default replication timeout */
#define DNA_DEFAULT_TIMEOUT 600 * 1000 /* 600 seconds in milliseconds */

/**
 * DNA config types
 */
#define DNA_TYPE "dnaType"
#define DNA_PREFIX "dnaPrefix"
#define DNA_NEXTVAL "dnaNextValue"
#define DNA_INTERVAL "dnaInterval"
#define DNA_GENERATE "dnaMagicRegen"
#define DNA_FILTER "dnaFilter"
#define DNA_SCOPE "dnaScope"
#define DNA_EXCLUDE_SCOPE "dnaExcludeScope"
#define DNA_REMOTE_BIND_DN "dnaRemoteBindDN"
#define DNA_REMOTE_BIND_PW "dnaRemoteBindCred"

/* since v2 */
#define DNA_MAXVAL "dnaMaxValue"
#define DNA_SHARED_CFG_DN "dnaSharedCfgDN"

/* Shared Config */
#define DNA_SHAREDCONFIG "dnaSharedConfig"
#define DNA_REMAINING "dnaRemainingValues"
#define DNA_THRESHOLD "dnaThreshold"
#define DNA_HOSTNAME "dnaHostname"
#define DNA_PORTNUM "dnaPortNum"
#define DNA_SECURE_PORTNUM "dnaSecurePortNum"
#define DNA_REMOTE_BUFSIZ 15 /* max size for bind method & protocol */
#define DNA_REMOTE_BIND_METHOD "dnaRemoteBindMethod"
#define DNA_REMOTE_CONN_PROT "dnaRemoteConnProtocol"

/* Bind Methods & Protocols */
#define DNA_METHOD_SIMPLE "SIMPLE"
#define DNA_METHOD_SSL "SSL"
#define DNA_METHOD_GSSAPI "SASL/GSSAPI"
#define DNA_METHOD_DIGESTMD5 "SASL/DIGEST-MD5"
#define DNA_PROT_LDAP "LDAP"
#define DNA_PROT_TLS "TLS"
#define DNA_PROT_SSL "SSL"
#define DNA_PROT_LDAPS "LDAPS"
#define DNA_PROT_STARTTLS "StartTLS"

/* For transferred ranges */
#define DNA_NEXT_RANGE "dnaNextRange"
#define DNA_RANGE_REQUEST_TIMEOUT "dnaRangeRequestTimeout"

/* Replication types */
#define DNA_REPL_BIND_DN "nsds5ReplicaBindDN"
#define DNA_REPL_BIND_DNGROUP "nsds5ReplicaBindDNGroup"
#define DNA_REPL_CREDS "nsds5ReplicaCredentials"
#define DNA_REPL_BIND_METHOD "nsds5ReplicaBindMethod"
#define DNA_REPL_TRANSPORT "nsds5ReplicaTransportInfo"
#define DNA_REPL_PORT "nsds5ReplicaPort"

#define DNA_FEATURE_DESC "Distributed Numeric Assignment"
#define DNA_EXOP_FEATURE_DESC "DNA Range Extension Request"
#define DNA_PLUGIN_DESC "Distributed Numeric Assignment plugin"
#define DNA_INT_PREOP_DESC "Distributed Numeric Assignment internal preop plugin"
#define DNA_POSTOP_DESC "Distributed Numeric Assignment postop plugin"
#define DNA_EXOP_DESC "Distributed Numeric Assignment range extension extop plugin"
#define DNA_BE_TXN_PREOP_DESC "Distributed Numeric Assignment backend txn preop plugin"

#define DNA_NEEDS_UPDATE "-2"

#define INTEGER_SYNTAX_OID "1.3.6.1.4.1.1466.115.121.1.27"

#define DNA_EXTEND_EXOP_REQUEST_OID "2.16.840.1.113730.3.5.10"
#define DNA_EXTEND_EXOP_RESPONSE_OID "2.16.840.1.113730.3.5.11"

static Slapi_PluginDesc pdesc = {DNA_FEATURE_DESC,
                                 VENDOR,
                                 DS_PACKAGE_VERSION,
                                 DNA_PLUGIN_DESC};

static Slapi_PluginDesc exop_pdesc = {DNA_EXOP_FEATURE_DESC,
                                      VENDOR,
                                      DS_PACKAGE_VERSION,
                                      DNA_EXOP_DESC};


/**
 * linked list of config entries
 */

struct configEntry
{
    PRCList list;
    char *dn;
    char **types;
    char *prefix;
    char *filter;
    Slapi_Filter *slapi_filter;
    char *generate;
    char *scope;
    Slapi_DN **excludescope;
    PRUint64 interval;
    PRUint64 threshold;
    char *shared_cfg_base;
    char *shared_cfg_dn;
    char *remote_binddn;
    char *remote_bindpw;
    PRUint64 timeout;
    /* This lock protects the 5 members below.  All
     * of the above members are safe to read as long
     * as you call dna_read_lock() first. */
    Slapi_Mutex *lock;
    PRUint64 nextval;
    PRUint64 maxval;
    PRUint64 remaining;
    PRUint64 next_range_lower;
    PRUint64 next_range_upper;
    /* This lock protects the extend_in_progress
     * member.  This is used to prevent us from
     * processing a range extention request and
     * trying to extend out own range at the same
     * time. */
    Slapi_Mutex *extend_lock;
    int extend_in_progress;
};

static PRCList *dna_global_config = NULL;
static Slapi_RWLock *g_dna_cache_lock;

static struct dnaServer *dna_global_servers = NULL;
static Slapi_RWLock *g_dna_cache_server_lock;

static void *_PluginID = NULL;
static const char *_PluginDN = NULL;

static char *hostname = NULL;
static char *portnum = NULL;
static char *secureportnum = NULL;

static Slapi_Eq_Context eq_ctx = {0};

/**
 * server struct for shared ranges
 */
struct dnaServer
{
    PRCList list;
    Slapi_DN *sdn;
    char *host;
    unsigned int port;
    unsigned int secureport;
    PRUint64 remaining;
    /* Remote replica settings from config */
    PRUint64 remote_defined;
    char *remote_bind_method;
    char *remote_conn_prot;
    char *remote_binddn;    /* contains pointer to main config binddn */
    char *remote_bindpw;    /* contains pointer to main config bindpw */
    struct dnaServer *next; /* used for the global server list */
};

static char *dna_extend_exop_oid_list[] = {
    DNA_EXTEND_EXOP_REQUEST_OID,
    NULL};


/**
 *
 * DNA plug-in management functions
 *
 */
int dna_init(Slapi_PBlock *pb);
static int dna_start(Slapi_PBlock *pb);
static int dna_close(Slapi_PBlock *pb);
static int dna_postop_init(Slapi_PBlock *pb);
static int dna_exop_init(Slapi_PBlock *pb);
static int dna_be_txn_preop_init(Slapi_PBlock *pb);

/**
 *
 * Local operation functions
 *
 */
static int dna_load_plugin_config(Slapi_PBlock *pb, int use_eventq);
static int dna_parse_config_entry(Slapi_PBlock *pb, Slapi_Entry *e, int apply);
static void dna_delete_config(PRCList *list);
static void dna_free_config_entry(struct configEntry **entry);
static int dna_load_host_port(void);

/**
 *
 * helpers
 *
 */
static char *dna_get_dn(Slapi_PBlock *pb);
static int dna_dn_is_config(char *dn);
static int dna_get_next_value(struct configEntry *config_entry,
                              char **next_value_ret);
static int dna_first_free_value(struct configEntry *config_entry,
                                PRUint64 *newval);
static int dna_fix_maxval(struct configEntry *config_entry,
                          int skip_range_request);
static void dna_notice_allocation(struct configEntry *config_entry,
                                  PRUint64 new,
                                  PRUint64 last);
static int dna_update_shared_config(struct configEntry *config_entry);
static void dna_update_config_event(time_t event_time, void *arg);
static int dna_get_shared_servers(struct configEntry *config_entry, PRCList **servers, int get_all);
static void dna_free_shared_server(struct dnaServer **server);
static void dna_delete_shared_servers(PRCList **servers);
static int dna_release_range(char *range_dn, PRUint64 *lower, PRUint64 *upper);
static int dna_request_range(struct configEntry *config_entry,
                             struct dnaServer *server,
                             PRUint64 *lower,
                             PRUint64 *upper);
static struct berval *dna_create_range_request(char *range_dn);
static int dna_update_next_range(struct configEntry *config_entry,
                                 PRUint64 lower,
                                 PRUint64 upper);
static int dna_activate_next_range(struct configEntry *config_entry);
static int dna_is_replica_bind_dn(char *range_dn, char *bind_dn);
static int dna_get_replica_bind_creds(char *range_dn, struct dnaServer *server, char **bind_dn, char **bind_passwd, char **bind_method, int *is_ssl, int *port);
static int dna_list_contains_type(char **list, char *type);
static int dna_list_contains_types(char **list, char **types);
static void dna_list_remove_type(char **list, char *type);
static int dna_is_multitype_range(struct configEntry *config_entry);
static void dna_create_valcheck_filter(struct configEntry *config_entry, PRUint64 value, char **filter);
static int dna_isrepl(Slapi_PBlock *pb);
static int dna_get_remote_config_info(struct dnaServer *server, char **bind_dn, char **bind_passwd, char **bind_method, int *is_ssl, int *port);
static int dna_load_shared_servers(void);
static void dna_delete_global_servers(void);
static int dna_get_shared_config_attr_val(struct configEntry *config_entry, char *attr, char *value);
static PRCList *dna_config_copy(void);
/**
 *
 * the ops (where the real work is done)
 *
 */
static int dna_config_check_post_op(Slapi_PBlock *pb);
static int dna_pre_op(Slapi_PBlock *pb, int modtype);
static int dna_mod_pre_op(Slapi_PBlock *pb);
static int dna_add_pre_op(Slapi_PBlock *pb);
static int dna_extend_exop(Slapi_PBlock *pb);
static int dna_extend_exop_backend(Slapi_PBlock *pb, Slapi_Backend **target);
static int dna_be_txn_pre_op(Slapi_PBlock *pb, int modtype);
static int dna_be_txn_add_pre_op(Slapi_PBlock *pb);
static int dna_be_txn_mod_pre_op(Slapi_PBlock *pb);

/**
 * debug functions - global, for the debugger
 */
void dna_dump_config(void);
void dna_dump_config_entry(struct configEntry *);

/*
 * During the plugin startup we delay the creation of the shared config entries
 * so all the other betxn plugins have time to start.  During the "delayed"
 * update config event we will need a copy of the global config, as we can not
 * hold the read lock while starting a transaction(potential deadlock).
 */
static PRCList *
dna_config_copy(void)
{
    PRCList *copy = (PRCList *)slapi_ch_calloc(1, sizeof(struct configEntry));
    PRCList *config_list;
    PR_INIT_CLIST(copy);
    int first = 1;


    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        config_list = PR_LIST_HEAD(dna_global_config);
        while (config_list != dna_global_config) {
            struct configEntry *new_entry = (struct configEntry *)slapi_ch_calloc(1, sizeof(struct configEntry));
            struct configEntry *config_entry = (struct configEntry *)config_list;

            new_entry->dn = slapi_ch_strdup(config_entry->dn);
            new_entry->types = slapi_ch_array_dup(config_entry->types);
            new_entry->prefix = slapi_ch_strdup(config_entry->prefix);
            new_entry->filter = slapi_ch_strdup(config_entry->filter);
            new_entry->slapi_filter = slapi_filter_dup(config_entry->slapi_filter);
            new_entry->generate = slapi_ch_strdup(config_entry->generate);
            new_entry->scope = slapi_ch_strdup(config_entry->scope);
            if (config_entry->excludescope == NULL) {
                new_entry->excludescope = NULL;
            } else {
                int i;

                for (i = 0; config_entry->excludescope[i]; i++)
                    ;
                new_entry->excludescope = (Slapi_DN **)slapi_ch_calloc(sizeof(Slapi_DN *), i + 1);
                for (i = 0; new_entry->excludescope[i]; i++) {
                    new_entry->excludescope[i] = slapi_sdn_dup(config_entry->excludescope[i]);
                }
            }
            new_entry->shared_cfg_base = slapi_ch_strdup(config_entry->shared_cfg_base);
            new_entry->shared_cfg_dn = slapi_ch_strdup(config_entry->shared_cfg_dn);
            new_entry->remote_binddn = slapi_ch_strdup(config_entry->remote_binddn);
            new_entry->remote_bindpw = slapi_ch_strdup(config_entry->remote_bindpw);
            new_entry->timeout = config_entry->timeout;
            new_entry->interval = config_entry->interval;
            new_entry->threshold = config_entry->threshold;
            new_entry->nextval = config_entry->nextval;
            new_entry->maxval = config_entry->maxval;
            new_entry->remaining = config_entry->remaining;
            new_entry->extend_in_progress = config_entry->extend_in_progress;
            new_entry->next_range_lower = config_entry->next_range_lower;
            new_entry->next_range_upper = config_entry->next_range_upper;
            new_entry->lock = NULL;
            new_entry->extend_lock = NULL;

            if (first) {
                PR_INSERT_LINK(&(new_entry->list), copy);
                first = 0;
            } else {
                PR_INSERT_BEFORE(&(new_entry->list), copy);
            }
            config_list = PR_NEXT_LINK(config_list);
        }
    }

    return copy;
}

/**
 *
 * Deal with cache locking
 *
 */
void
dna_read_lock(void)
{
    slapi_rwlock_rdlock(g_dna_cache_lock);
}

void
dna_write_lock(void)
{
    slapi_rwlock_wrlock(g_dna_cache_lock);
}

void
dna_unlock(void)
{
    slapi_rwlock_unlock(g_dna_cache_lock);
}

void
dna_server_read_lock(void)
{
    slapi_rwlock_rdlock(g_dna_cache_server_lock);
}

void
dna_server_write_lock(void)
{
    slapi_rwlock_wrlock(g_dna_cache_server_lock);
}

void
dna_server_unlock(void)
{
    slapi_rwlock_unlock(g_dna_cache_server_lock);
}

/**
 *
 * Get the dna plug-in version
 *
 */
int
dna_version(void)
{
    return DNA_PLUGIN_VERSION;
}

/**
 * Plugin identity mgmt
 */
void
setPluginID(void *pluginID)
{
    _PluginID = pluginID;
}

void *
getPluginID(void)
{
    return _PluginID;
}

void
setPluginDN(const char *pluginDN)
{
    _PluginDN = pluginDN;
}

const char *
getPluginDN(void)
{
    return _PluginDN;
}

/*
    dna_init
    -------------
    adds our callbacks to the list
*/
int
dna_init(Slapi_PBlock *pb)
{
    int status = DNA_SUCCESS;
    char *plugin_identity = NULL;
    char *plugin_type = NULL;
    int preadd = SLAPI_PLUGIN_BE_PRE_ADD_FN;
    int premod = SLAPI_PLUGIN_BE_PRE_MODIFY_FN;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_init\n");

    /**
     * Store the plugin identity for later use.
     * Used for internal operations
     */

    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &plugin_identity);
    PR_ASSERT(plugin_identity);
    setPluginID(plugin_identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                         (void *)dna_start) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                         (void *)dna_close) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *)&pdesc) != 0 ||
        slapi_pblock_set(pb, premod, (void *)dna_mod_pre_op) != 0 ||
        slapi_pblock_set(pb, preadd, (void *)dna_add_pre_op) != 0) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_init - Failed to register plugin\n");
        status = DNA_FAILURE;
    }

    if (status == DNA_SUCCESS) {
        plugin_type = "betxnpostoperation";
        /* the config change checking post op */
        if (slapi_register_plugin(plugin_type,     /* op type */
                                  1,               /* Enabled */
                                  "dna_init",      /* this function desc */
                                  dna_postop_init, /* init func for post op */
                                  DNA_POSTOP_DESC, /* plugin desc */
                                  NULL,            /* ? */
                                  plugin_identity  /* access control */
                                  )) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_init - Failed to register postop plugin\n");
            status = DNA_FAILURE;
        }
    }

    if ((status == DNA_SUCCESS) &&
        /* the range extension extended operation */
        slapi_register_plugin("betxnextendedop", /* op type */
                              1,                 /* Enabled */
                              "dna_init",        /* this function desc */
                              dna_exop_init,     /* init func for exop */
                              DNA_EXOP_DESC,     /* plugin desc */
                              NULL,              /* ? */
                              plugin_identity    /* access control */
                              )) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_init - Failed to register plugin\n");
        status = DNA_FAILURE;
    }

    if (status == DNA_SUCCESS) {
        plugin_type = "betxnpreoperation";

        /* the config change checking post op */
        if (slapi_register_plugin(plugin_type,           /* op type */
                                  1,                     /* Enabled */
                                  "dna_init",            /* this function desc */
                                  dna_be_txn_preop_init, /* init func for post op */
                                  DNA_BE_TXN_PREOP_DESC, /* plugin desc */
                                  NULL,                  /* ? */
                                  plugin_identity        /* access control */
                                  )) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_init - Failed to register be_txn_pre_op plugin\n");
            status = DNA_FAILURE;
        }
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_init\n");
    return status;
}

static int
dna_postop_init(Slapi_PBlock *pb)
{
    int status = DNA_SUCCESS;
    int addfn = SLAPI_PLUGIN_BE_TXN_POST_ADD_FN;
    int delfn = SLAPI_PLUGIN_BE_TXN_POST_DELETE_FN;
    int modfn = SLAPI_PLUGIN_BE_TXN_POST_MODIFY_FN;
    int mdnfn = SLAPI_PLUGIN_BE_TXN_POST_MODRDN_FN;
    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *)&pdesc) != 0 ||
        slapi_pblock_set(pb, addfn, (void *)dna_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, mdnfn, (void *)dna_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, delfn, (void *)dna_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, modfn, (void *)dna_config_check_post_op) != 0) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_postop_init - Failed to register plugin\n");
        status = DNA_FAILURE;
    }

    return status;
}


static int
dna_exop_init(Slapi_PBlock *pb)
{
    int status = DNA_SUCCESS;

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *)&exop_pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST,
                         (void *)dna_extend_exop_oid_list) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN,
                         (void *)dna_extend_exop) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_BACKEND_FN,
                         (void *)dna_extend_exop_backend) != 0) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_exop_init - Failed to register plugin\n");
        status = DNA_FAILURE;
    }

    return status;
}

static int
dna_be_txn_preop_init(Slapi_PBlock *pb)
{
    int status = DNA_SUCCESS;

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_PRE_ADD_FN, (void *)dna_be_txn_add_pre_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_PRE_MODIFY_FN, (void *)dna_be_txn_mod_pre_op) != 0) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_init - Failed to register be_txn_pre_op plugin\n");
        status = DNA_FAILURE;
    }

    return status;
}

/*
    dna_start
    --------------
    Kicks off the config cache.
    It is called after dna_init.
*/
static int
dna_start(Slapi_PBlock *pb)
{
    Slapi_DN *pluginsdn = NULL;
    const char *plugindn = NULL;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_start\n");

    g_dna_cache_lock = slapi_new_rwlock();
    if (!g_dna_cache_lock) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_start - Global config lock creation failed\n");
        return DNA_FAILURE;
    }

    g_dna_cache_server_lock = slapi_new_rwlock();
    if (!g_dna_cache_server_lock) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_start - Global server lock creation failed\n");
        return DNA_FAILURE;
    }

    /**
     *    Get the plug-in target dn from the system
     *    and store it for future use. This should avoid
     *    hardcoding of DN's in the code.
     */
    slapi_pblock_get(pb, SLAPI_TARGET_SDN, &pluginsdn);
    if (NULL == pluginsdn || 0 == slapi_sdn_get_ndn_len(pluginsdn)) {
        slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                      "dna_start - Had to use hard coded config dn\n");
        plugindn = DNA_DN;
    } else {
        plugindn = slapi_sdn_get_dn(pluginsdn);
        slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                      "dna_start - Config at %s\n", plugindn);
    }

    setPluginDN(plugindn);

    /* We need the host and port number of this server
     * in case shared config is enabled for any of the
     * ranges we are managing. */
    if (dna_load_host_port() != DNA_SUCCESS) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_start - Unable to load host and port information\n");
    }

    /*
     * Load the config for our plug-in
     */
    dna_global_config = (PRCList *)
        slapi_ch_calloc(1, sizeof(struct configEntry));
    PR_INIT_CLIST(dna_global_config);

    if (dna_load_plugin_config(pb, 1 /* use eventq */) != DNA_SUCCESS) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_start - Unable to load plug-in configuration\n");
        return DNA_FAILURE;
    }

    /*
     * Load all shared server configs
     */
    if (dna_load_shared_servers()) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_start - Shared config server initialization failed.\n");
        return DNA_FAILURE;
    }

    slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                  "dna_start - Ready for service\n");
    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_start\n");

    return DNA_SUCCESS;
}

/*
    dna_close
    --------------
    closes down the cache
*/
static int
dna_close(Slapi_PBlock *pb __attribute__((unused)))
{
    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_close\n");

    slapi_eq_cancel_rel(eq_ctx);
    dna_delete_config(NULL);
    slapi_ch_free((void **)&dna_global_config);
    slapi_destroy_rwlock(g_dna_cache_lock);
    g_dna_cache_lock = NULL;

    dna_delete_global_servers();
    slapi_destroy_rwlock(g_dna_cache_server_lock);
    g_dna_cache_server_lock = NULL;

    slapi_ch_free_string(&hostname);
    slapi_ch_free_string(&portnum);
    slapi_ch_free_string(&secureportnum);

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_close\n");

    return DNA_SUCCESS;
}

static int
dna_parse_exop_ber(Slapi_PBlock *pb, char **shared_dn)
{
    int ret = -1; /* What's a better default? */
    char *oid = NULL;
    struct berval *reqdata = NULL;
    BerElement *tmp_bere = NULL;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "----> dna_parse_exop_ber\n");

    /* Fetch the request OID */
    slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_OID, &oid);
    if (!oid) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_exop_ber - Unable to retrieve request OID.\n");
        goto out;
    }

    /* Make sure the request OID is correct. */
    if (strcmp(oid, DNA_EXTEND_EXOP_REQUEST_OID) != 0) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_exop_ber - Received incorrect request OID.\n");
        goto out;
    }

    /* Fetch the request data */
    slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_VALUE, &reqdata);
    if (!BV_HAS_DATA(reqdata)) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_exop_ber - No request data received.\n");
        goto out;
    }

    /* decode the exop */
    tmp_bere = ber_init(reqdata);
    if (tmp_bere == NULL) {
        goto out;
    }

    if (ber_scanf(tmp_bere, "{a}", shared_dn) == LBER_ERROR) {
        ret = LDAP_PROTOCOL_ERROR;
        goto out;
    }

    ret = LDAP_SUCCESS;

out:
    if (NULL != tmp_bere) {
        ber_free(tmp_bere, 1);
        tmp_bere = NULL;
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<---- dna_parse_exop_ber %s\n", *shared_dn);
    return ret;
}

/*
 * Free the global linkedl ist of shared servers
 */
static void
dna_delete_global_servers(void)
{
    struct dnaServer *server, *next;

    if (dna_global_servers) {
        server = dna_global_servers;
        while (server) {
            next = server->next;
            dna_free_shared_server(&server);
            server = next;
        }
        dna_global_servers = NULL;
    }
}

/*
 * Look through the global config entries, and build a global
 * shared server config list.
 */
static int
dna_load_shared_servers(void)
{
    struct configEntry *config_entry = NULL;
    struct dnaServer *server = NULL, *global_servers = NULL;
    PRCList *server_list = NULL;
    PRCList *config_list = NULL;
    int freed_servers = 0;
    int ret = 0;

    /* Now build the new list. */
    dna_write_lock();
    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        config_list = PR_LIST_HEAD(dna_global_config);
        while (config_list != dna_global_config) {
            PRCList *shared_list = NULL;
            config_entry = (struct configEntry *)config_list;

            if (dna_get_shared_servers(config_entry,
                                       &shared_list,
                                       1 /* get all the servers */)) {
                dna_unlock();
                return -1;
            }

            dna_server_write_lock();
            if (!freed_servers) {
                dna_delete_global_servers();
                freed_servers = 1;
            }
            if (shared_list) {
                server_list = PR_LIST_HEAD(shared_list);
                while (server_list != shared_list) {
                    server = (struct dnaServer *)server_list;
                    if (global_servers == NULL) {
                        dna_global_servers = global_servers = server;
                    } else {
                        global_servers->next = server;
                        global_servers = server;
                    }
                    server_list = PR_NEXT_LINK(server_list);
                }
                slapi_ch_free((void **)&shared_list);
            }
            dna_server_unlock();

            config_list = PR_NEXT_LINK(config_list);
        }
    }
    dna_unlock();

    return ret;
}

/*
 * config looks like this
 * - cn=myplugin
 * --- cn=posix
 * ------ cn=accounts
 * ------ cn=groups
 * --- cn=samba
 * --- cn=etc
 * ------ cn=etc etc
 */
static int
dna_load_plugin_config(Slapi_PBlock *pb, int use_eventq)
{
    int status = DNA_SUCCESS;
    int result;
    int i;
    time_t now;
    Slapi_PBlock *search_pb;
    Slapi_Entry **entries = NULL;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_load_plugin_config %s\n",
                  use_eventq ? "using event queue" : "");

    dna_write_lock();
    dna_delete_config(NULL);

    search_pb = slapi_pblock_new();

    slapi_search_internal_set_pb(search_pb, getPluginDN(),
                                 LDAP_SCOPE_SUBTREE, "objectclass=*",
                                 NULL, 0, NULL, NULL, getPluginID(), 0);
    slapi_search_internal_pb(search_pb);
    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_RESULT, &result);

    if (LDAP_SUCCESS != result) {
        status = DNA_FAILURE;
        dna_unlock();
        goto cleanup;
    }

    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                     &entries);
    if (NULL == entries || NULL == entries[0]) {
        status = DNA_SUCCESS;
        dna_unlock();
        goto cleanup;
    }

    for (i = 0; (entries[i] != NULL); i++) {
        /* We don't care about the status here because we may have
         * some invalid config entries, but we just want to continue
         * looking for valid ones. */
        dna_parse_config_entry(pb, entries[i], 1);
    }

    dna_unlock();

    if (use_eventq) {
        /* Setup an event to update the shared config 30
         * seconds from now.  We need to do this since
         * performing the operation at this point when
         * starting up  would cause the change to not
         * get changelogged. */
        now = slapi_current_rel_time_t();
        eq_ctx = slapi_eq_once_rel(dna_update_config_event, NULL, now + 30);
    } else {
        dna_update_config_event(0, NULL);
    }

cleanup:
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);
    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_load_plugin_config\n");

    return status;
}

/*
 * dna_parse_config_entry()
 *
 * Parses a single config entry.  If apply is non-zero, then
 * we will load and start using the new config.  You can simply
 * validate config without making any changes by setting apply
 * to 0.
 *
 * Returns DNA_SUCCESS if the entry is valid and DNA_FAILURE
 * if it is invalid.
 */
static int
dna_parse_config_entry(Slapi_PBlock *pb, Slapi_Entry *e, int apply)
{
    char *value;
    struct configEntry *entry = NULL;
    struct configEntry *config_entry;
    PRCList *list;
    int entry_added = 0;
    int i = 0;
    int ret = DNA_SUCCESS;
    char **plugin_attr_values;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_parse_config_entry\n");

    /* If this is the main DNA plug-in
     * config entry, just bail. */
    if (strcasecmp(getPluginDN(), slapi_entry_get_ndn(e)) == 0) {
        ret = DNA_SUCCESS;
        goto bail;
    }

    entry = (struct configEntry *)slapi_ch_calloc(1, sizeof(struct configEntry));

    value = slapi_entry_get_ndn(e);
    if (value) {
        entry->dn = slapi_ch_strdup(value);
    }

    slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                  "dna_parse_config_entry - dn [%s]\n", entry->dn);

    entry->types = slapi_entry_attr_get_charray(e, DNA_TYPE);
    if (entry->types == NULL) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry - The %s config "
                      "setting is required for range %s.\n",
                      DNA_TYPE, entry->dn);
        ret = DNA_FAILURE;
        goto bail;
    }

    for (i = 0; entry->types && entry->types[i]; i++) {
        if (!slapi_attr_syntax_exists(entry->types[i])) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - dnaType (%s) does "
                          "not exist.\n",
                          entry->types[i]);
            ret = DNA_FAILURE;
            goto bail;
        }
        slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                      "----------> %s [%s]\n", DNA_TYPE, entry->types[i]);
    }

    value = slapi_entry_attr_get_charptr(e, DNA_NEXTVAL);
    if (value) {
        entry->nextval = strtoull(value, 0, 0);
        slapi_ch_free_string(&value);
    } else {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry - The %s config "
                      "setting is required for range %s.\n",
                      DNA_NEXTVAL, entry->dn);
        ret = DNA_FAILURE;
        goto bail;
    }

    slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                  "dna_parse_config_entry - %s [%" PRIu64 "]\n", DNA_NEXTVAL,
                  entry->nextval);

    value = slapi_entry_attr_get_charptr(e, DNA_PREFIX);
    if (value && value[0]) {
        entry->prefix = value;
    } else {
        /* TODO - If a prefix is not  defined, then we need to ensure
         * that the proper matching rule is in place for this
         * attribute type.  We require this since we internally
         * perform a sorted range search on what we assume to
         * be an INTEGER syntax. */
        slapi_ch_free_string(&value);
    }

    slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                  "dna_parse_config_entry - %s [%s]\n", DNA_PREFIX, entry->prefix);

    /* Set the default interval to 1 */
    entry->interval = 1;

    value = slapi_entry_attr_get_charptr(e, DNA_INTERVAL);
    if (value) {
        errno = 0;
        entry->interval = strtoull(value, 0, 0);
        if (entry->interval == 0 || errno == ERANGE) {
            slapi_log_err(SLAPI_LOG_WARNING, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - Invalid value for dnaInterval (%s), "
                          "Using default value of 1\n", value);
            entry->interval = 1;
        }
        slapi_ch_free_string(&value);
    }

    slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                  "dna_parse_config_entry - %s [%" PRIu64 "]\n", DNA_INTERVAL, entry->interval);

    value = slapi_entry_attr_get_charptr(e, DNA_GENERATE);
    if (value) {
        entry->generate = value;
        slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry - %s [%s]\n", DNA_GENERATE, entry->generate);
    }

    value = slapi_entry_attr_get_charptr(e, DNA_FILTER);
    if (value) {
        entry->filter = value;
        if (NULL == (entry->slapi_filter = slapi_str2filter(value))) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - Invalid search filter in entry [%s]: [%s]\n",
                          entry->dn, value);
            ret = DNA_FAILURE;
            goto bail;
        }
    } else {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry - The %s config "
                      "setting is required for range %s.\n",
                      DNA_FILTER, entry->dn);
        ret = DNA_FAILURE;
        goto bail;
    }

    slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                  "dna_parse_config_entry - %s [%s]\n", DNA_FILTER, value);

    value = slapi_entry_attr_get_charptr(e, DNA_SCOPE);
    if (value) {
        Slapi_DN *test_dn = NULL;

        /* TODO - Allow multiple scope settings for a single range.  This may
         * make ordering the scopes tough when we put them in the clist. */
        entry->scope = value;
        /* Check if the scope is a valid DN.  We want to normalize the DN
         * first to allow old config entries with things like spaces between
         * RDN elements to still work. */
        test_dn = slapi_sdn_new_dn_byref(value);
        if (slapi_dn_syntax_check(NULL, (char *)slapi_sdn_get_ndn(test_dn), 1) == 1) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - Invalid DN used as scope in entry [%s]: [%s]\n",
                          entry->dn, value);
            ret = DNA_FAILURE;
            slapi_sdn_free(&test_dn);
            goto bail;
        }
        slapi_sdn_free(&test_dn);
    } else {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry - The %s config "
                      "config setting is required for range %s.\n",
                      DNA_SCOPE, entry->dn);
        ret = DNA_FAILURE;
        goto bail;
    }

    slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                  "dna_parse_config_entry - %s [%s]\n", DNA_SCOPE, entry->scope);

    plugin_attr_values = slapi_entry_attr_get_charray(e, DNA_EXCLUDE_SCOPE);
    if (plugin_attr_values) {
        int j = 0;

        /* Allocate the array of excluded scopes */
        for (i = 0; plugin_attr_values[i]; i++)
            ;
        entry->excludescope = (Slapi_DN **)slapi_ch_calloc(sizeof(Slapi_DN *), i + 1);

        /* Copy them in the config at the condition they are valid DN */
        for (i = 0; plugin_attr_values[i]; i++) {
            if (slapi_dn_syntax_check(NULL, plugin_attr_values[i], 1) == 1) {
                slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                              "dna_parse_config_entry - Ignoring invalid DN used as excluded scope: [%s]\n", plugin_attr_values[i]);
                slapi_ch_free_string(&plugin_attr_values[i]);
            } else {
                entry->excludescope[j++] = slapi_sdn_new_dn_passin(plugin_attr_values[i]);
            }
        }
        slapi_ch_free((void **)&plugin_attr_values);
    }
    for (i = 0; entry->excludescope && entry->excludescope[i]; i++) {
        slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry - %s[%d] [%s]\n", DNA_EXCLUDE_SCOPE, i, slapi_sdn_get_dn(entry->excludescope[i]));
    }

    /* optional, if not specified set -1 which is converted to the max unsigned
     * value */
    value = slapi_entry_attr_get_charptr(e, DNA_MAXVAL);
    if (value) {
        entry->maxval = strtoull(value, 0, 0);
        slapi_ch_free_string(&value);
    } else {
        entry->maxval = -1;
    }

    slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                  "dna_parse_config_entry - %s [%" PRIu64 "]\n", DNA_MAXVAL,
                  entry->maxval);

    /* get the global bind dn and password(if any) */
    value = slapi_entry_attr_get_charptr(e, DNA_REMOTE_BIND_DN);
    if (value) {
        Slapi_DN *sdn = NULL;
        char *normdn = NULL;

        sdn = slapi_sdn_new_dn_passin(value);
        if (!sdn) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - Unable to create "
                          "slapi_dn from dnaRemoteBindDN (%s)\n",
                          value);
            ret = DNA_FAILURE;
            slapi_ch_free_string(&value);
            goto bail;
        }
        normdn = (char *)slapi_sdn_get_dn(sdn);
        if (NULL == normdn) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - Failed to normalize dn: "
                          "%s\n",
                          value);
            ret = DNA_FAILURE;
            slapi_sdn_free(&sdn);
            goto bail;
        }
        entry->remote_binddn = slapi_ch_strdup(normdn);
        slapi_sdn_free(&sdn);
    }
    /* now grab the password */
    entry->remote_bindpw = slapi_entry_attr_get_charptr(e, DNA_REMOTE_BIND_PW);

    /* validate that we have both a bind dn or password, or we have none */
    if ((entry->remote_bindpw != NULL && entry->remote_binddn == NULL) ||
        (entry->remote_binddn != NULL && entry->remote_bindpw == NULL)) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry - Invalid remote bind DN and password settings.\n");
        ret = DNA_FAILURE;
        goto bail;
    }

    value = slapi_entry_attr_get_charptr(e, DNA_SHARED_CFG_DN);
    if (value) {
        Slapi_DN *sdn = NULL;
        char *normdn = NULL;
        char *attrs[2];

        sdn = slapi_sdn_new_dn_passin(value);

        if (!sdn) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - Unable to create "
                          "slapi_dn (%s)\n",
                          value);
            ret = DNA_FAILURE;
            slapi_ch_free_string(&value);
            goto bail;
        }
        /* We don't need attributes */
        attrs[0] = "cn";
        attrs[1] = NULL;
        /* Make sure that the shared config entry exists. */
        if(slapi_search_internal_get_entry(sdn, attrs, NULL, getPluginID()) != LDAP_SUCCESS) {
            /* We didn't locate the shared config container entry. Log
             * a message and skip this config entry. */
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - Unable to locate "
                          "shared configuration entry (%s)\n",
                          value);
            ret = DNA_FAILURE;
            slapi_sdn_free(&sdn);
            goto bail;
        }

        normdn = (char *)slapi_sdn_get_dn(sdn);
        if (NULL == normdn) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - Failed to normalize dn: "
                          "%s\n",
                          value);
            ret = DNA_FAILURE;
            slapi_sdn_free(&sdn);
            goto bail;
        }
        entry->shared_cfg_base = slapi_ch_strdup(normdn);
        slapi_sdn_free(&sdn);

        /* We prepend the host & port of this instance as a
         * multi-part RDN for the shared config entry. */
        normdn = slapi_create_dn_string("%s=%s+%s=%s,%s", DNA_HOSTNAME,
                                        hostname, DNA_PORTNUM, portnum,
                                        entry->shared_cfg_base);
        if (NULL == normdn) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - Failed to create dn: "
                          "%s=%s+%s=%s,%s",
                          DNA_HOSTNAME,
                          hostname, DNA_PORTNUM, portnum, value);
            ret = DNA_FAILURE;
            goto bail;
        }
        entry->shared_cfg_dn = normdn;

        slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry - %s [%s]\n", DNA_SHARED_CFG_DN,
                      entry->shared_cfg_base);
    }

    value = slapi_entry_attr_get_charptr(e, DNA_THRESHOLD);
    if (value) {
        entry->threshold = strtoull(value, 0, 0);

        slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry - %s [%s]\n", DNA_THRESHOLD, value);

        if (entry->threshold <= 0) {
            entry->threshold = 1;
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "----------> %s too low, setting to [%s]\n", DNA_THRESHOLD, value);
        }

        slapi_ch_free_string(&value);
    } else {
        entry->threshold = 1;
    }

    slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                  "dna_parse_config_entry - %s [%" PRIu64 "]\n", DNA_THRESHOLD,
                  entry->threshold);

    value = slapi_entry_attr_get_charptr(e, DNA_RANGE_REQUEST_TIMEOUT);
    if (value) {
        entry->timeout = strtoull(value, 0, 0);
        slapi_ch_free_string(&value);
    } else {
        entry->timeout = DNA_DEFAULT_TIMEOUT;
    }

    slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                  "dna_parse_config_entry - %s [%" PRIu64 "]\n", DNA_RANGE_REQUEST_TIMEOUT,
                  entry->timeout);

    value = slapi_entry_attr_get_charptr(e, DNA_NEXT_RANGE);
    if (value) {
        char *p = NULL;

        /* the next range value is in the form "<lower>-<upper>" */
        if ((p = strchr(value, '-')) != NULL) {
            *p = '\0';
            ++p;
            entry->next_range_lower = strtoull(value, 0, 0);
            entry->next_range_upper = strtoull(p, 0, 0);

            /* validate that upper is greater than lower */
            if (entry->next_range_upper <= entry->next_range_lower) {
                slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                              "dna_parse_config_entry: Illegal %s "
                              "setting specified for range %s.  Legal "
                              "format is <lower>-<upper>.\n",
                              DNA_NEXT_RANGE, entry->dn);
                ret = DNA_FAILURE;
                entry->next_range_lower = 0;
                entry->next_range_upper = 0;
            }

            /* make sure next range doesn't overlap with
             * the active range */
            if (((entry->next_range_upper <= entry->maxval) &&
                 (entry->next_range_upper >= entry->nextval)) ||
                ((entry->next_range_lower <= entry->maxval) &&
                 (entry->next_range_lower >= entry->nextval))) {
                slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                              "dna_parse_config_entry: Illegal %s "
                              "setting specified for range %s.  %s "
                              "overlaps with the active range.\n",
                              DNA_NEXT_RANGE, entry->dn, DNA_NEXT_RANGE);
                ret = DNA_FAILURE;
                entry->next_range_lower = 0;
                entry->next_range_upper = 0;
            }
        } else {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry: Illegal %s "
                          "setting specified for range %s.  Legal "
                          "format is <lower>-<upper>.\n",
                          DNA_NEXT_RANGE, entry->dn);
            ret = DNA_FAILURE;
        }

        slapi_ch_free_string(&value);
    }

    /* If we were only called to validate config, we can
     * just bail out before applying the config changes */
    if (apply == 0) {
        goto bail;
    }

    /* Calculate number of remaining values. */
    if (entry->next_range_lower != 0) {
        entry->remaining = ((entry->next_range_upper - entry->next_range_lower + 1) /
                            entry->interval) +
                           ((entry->maxval - entry->nextval + 1) /
                            entry->interval);
    } else if (entry->nextval >= entry->maxval) {
        entry->remaining = 0;
    } else {
        entry->remaining = ((entry->maxval - entry->nextval + 1) /
                            entry->interval);
    }

    /* create the new value lock for this range */
    entry->lock = slapi_new_mutex();
    if (!entry->lock) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry: Unable to create lock "
                      "for range %s.\n",
                      entry->dn);
        ret = DNA_FAILURE;
        goto bail;
    }

    /* Check if the shared config base matches the config scope and filter */
    if (entry->scope && slapi_dn_issuffix(entry->shared_cfg_base, entry->scope)) {
        if (entry->slapi_filter) {
            ret = slapi_vattr_filter_test(pb, e, entry->slapi_filter, 0);
            if (LDAP_SUCCESS == ret) {
                slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM, "dna_parse_config_entry - "
                                                                   "Shared config entry (%s) matches scope \"%s\", and filter \"%s\" "
                                                                   "of the DNA config entry (%s).\n",
                              entry->shared_cfg_base,
                              entry->scope, entry->filter, entry->dn);
                ret = DNA_FAILURE;
                goto bail;
            }
        }
    }

    /**
     * Finally add the entry to the list.
     * We sort by scope dn length with longer
     * dn's first - this allows the scope
     * checking code to be simple and quick and
     * cunningly linear.
     */
    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        list = PR_LIST_HEAD(dna_global_config);
        while (list != dna_global_config) {
            config_entry = (struct configEntry *)list;

            if (slapi_dn_issuffix(entry->scope, config_entry->scope)) {
                PR_INSERT_BEFORE(&(entry->list), list);
                slapi_log_err(SLAPI_LOG_CONFIG,
                              DNA_PLUGIN_SUBSYSTEM,
                              "dna_parse_config_entry - store [%s] before [%s] \n", entry->scope,
                              config_entry->scope);
                entry_added = 1;
                break;
            }

            list = PR_NEXT_LINK(list);

            if (dna_global_config == list) {
                /* add to tail */
                PR_INSERT_BEFORE(&(entry->list), list);
                slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                              "dna_parse_config_entry - store [%s] at tail\n", entry->scope);
                entry_added = 1;
                break;
            }
        }
    } else {
        /* first entry */
        PR_INSERT_LINK(&(entry->list), dna_global_config);
        slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                      "dna_parse_config_entry - store [%s] at head \n", entry->scope);
        entry_added = 1;
    }

bail:
    if (0 == entry_added) {
        /* Don't log error if we weren't asked to apply config */
        if ((apply != 0) && (entry != NULL)) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_parse_config_entry - Invalid config entry "
                          "[%s] skipped\n",
                          entry->dn);
        }
        dna_free_config_entry(&entry);
    } else {
        ret = DNA_SUCCESS;
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_parse_config_entry\n");

    return ret;
}

static void
dna_free_config_entry(struct configEntry **entry)
{
    struct configEntry *e;
    if ((entry == NULL) || (*entry == NULL)) {
        return;
    }

    e = *entry;
    if (e->dn) {
        slapi_log_err(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                      "dna_free_config_entry - Freeing config entry [%s]\n", e->dn);
        slapi_ch_free_string(&e->dn);
    }

    slapi_ch_array_free(e->types);
    slapi_ch_free_string(&e->prefix);
    slapi_ch_free_string(&e->filter);
    slapi_filter_free(e->slapi_filter, 1);
    slapi_ch_free_string(&e->generate);
    slapi_ch_free_string(&e->scope);
    if (e->excludescope) {
        int i;

        for (i = 0; e->excludescope[i]; i++) {
            slapi_sdn_free(&e->excludescope[i]);
        }
        slapi_ch_free((void **)&e->excludescope);
    }
    slapi_ch_free_string(&e->shared_cfg_base);
    slapi_ch_free_string(&e->shared_cfg_dn);
    slapi_ch_free_string(&e->remote_binddn);
    slapi_ch_free_string(&e->remote_bindpw);

    slapi_destroy_mutex(e->lock);

    slapi_ch_free((void **)entry);
}

static void
dna_delete_configEntry(PRCList *entry)
{
    PR_REMOVE_LINK(entry);
    dna_free_config_entry((struct configEntry **)&entry);
}

static void
dna_delete_config(PRCList *list)
{
    PRCList *list_entry, *delete_list;

    if (list) {
        delete_list = list;
    } else {
        delete_list = dna_global_config;
    }
    while (!PR_CLIST_IS_EMPTY(delete_list)) {
        list_entry = PR_LIST_HEAD(delete_list);
        dna_delete_configEntry(list_entry);
    }

    return;
}

static void
dna_free_shared_server(struct dnaServer **server)
{
    struct dnaServer *s;

    if ((NULL == server) || (NULL == *server)) {
        return;
    }
    s = *server;
    slapi_sdn_free(&s->sdn);
    slapi_ch_free_string(&s->host);
    slapi_ch_free_string(&s->remote_bind_method);
    slapi_ch_free_string(&s->remote_conn_prot);
    slapi_ch_free((void **)server);
}

static void
dna_delete_shared_servers(PRCList **servers)
{
    PRCList *server;

    while (!PR_CLIST_IS_EMPTY(*servers)) {
        server = PR_LIST_HEAD(*servers);
        PR_REMOVE_LINK(server);
        dna_free_shared_server((struct dnaServer **)&server);
    }

    slapi_ch_free((void **)servers);

    return;
}

static int
dna_load_host_port(void)
{
    Slapi_PBlock *pb = NULL;
    int status = DNA_SUCCESS;
    Slapi_Entry *e = NULL;
    Slapi_DN *config_dn = NULL;
    char *attrs[4];

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_load_host_port\n");

    attrs[0] = "nsslapd-localhost";
    attrs[1] = "nsslapd-port";
    attrs[2] = "nsslapd-secureport";
    attrs[3] = NULL;

    config_dn = slapi_sdn_new_ndn_byref("cn=config");
    if (config_dn) {
        slapi_search_get_entry(&pb, config_dn, attrs, &e, getPluginID());
        slapi_sdn_free(&config_dn);
    }

    if (e) {
        hostname = slapi_entry_attr_get_charptr(e, "nsslapd-localhost");
        portnum = slapi_entry_attr_get_charptr(e, "nsslapd-port");
        secureportnum = slapi_entry_attr_get_charptr(e, "nsslapd-secureport");
    }
    slapi_search_get_entry_done(&pb);

    if (!hostname || !portnum) {
        status = DNA_FAILURE;
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_load_host_port\n");

    return status;
}

/*
 * dna_update_config_event()
 *
 * Event queue callback that we use to do the initial
 * update of the shared config entries shortly after
 * startup.
 *
 * Since we need to start a backend transaction, a copy/snapshot of the global
 * config is used, and then freed.
 */
static void
dna_update_config_event(time_t event_time __attribute__((unused)), void *arg __attribute__((unused)))
{
    Slapi_PBlock *pb = NULL;
    struct configEntry *config_entry = NULL;
    PRCList *copy = NULL, *list = NULL;

    /* Get the read lock so we can copy the config */
    dna_read_lock();

    /* Loop through all config entries and update the shared config entries. */
    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        /*
         * We need to use a copy of the config because we can not hold
         * the read lock and start a backend transaction.
         */
        copy = dna_config_copy();
        dna_unlock();

        /* Create the pblock.  We'll reuse it for all shared config updates. */
        if ((pb = slapi_pblock_new()) == NULL)
            goto bail;

        list = PR_LIST_HEAD(copy);
        while (list != copy) {
            config_entry = (struct configEntry *)list;

            /* If a shared config dn is set, update the shared config. */
            if (config_entry->shared_cfg_dn != NULL) {
                int rc = 0;
                Slapi_PBlock *dna_pb = NULL;
                Slapi_DN *sdn = slapi_sdn_new_normdn_byref(config_entry->shared_cfg_dn);
                Slapi_Backend *be = slapi_be_select(sdn);

                slapi_sdn_free(&sdn);
                if (be) {
                    dna_pb = slapi_pblock_new();
                    slapi_pblock_set(dna_pb, SLAPI_BACKEND, be);
                    /* We need to start transaction to avoid the deadlock */
                    rc = slapi_back_transaction_begin(dna_pb);
                    if (rc == 0) {

                        /* First delete the existing shared config entry.  This
                         * will allow the entry to be updated for things like
                         * port number changes, etc. */
                        slapi_delete_internal_set_pb(pb, config_entry->shared_cfg_dn,
                                                     NULL, NULL, getPluginID(), 0);

                        /* We don't care about the results */
                        slapi_delete_internal_pb(pb);

                        /* Now force the entry to be recreated */
                        rc = dna_update_shared_config(config_entry);

                        if (0 == rc) {
                            slapi_back_transaction_commit(dna_pb);
                        } else {
                            if (slapi_back_transaction_abort(dna_pb) != 0) {
                                slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM, "dna_update_config_event - "
                                                                                   "Failed to abort transaction!\n");
                            }
                        }
                        slapi_pblock_destroy(dna_pb);
                        slapi_pblock_init(pb);
                    } else {
                        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                                      "dna_update_config_event - Failed to start transaction\n");
                    }
                }
            }

            list = PR_NEXT_LINK(list);
        }
        dna_delete_config(copy);
        slapi_ch_free((void **)&copy);
    } else {
        dna_unlock();
    }

bail:
    slapi_pblock_destroy(pb);
}

/****************************************************
    Distributed ranges Helpers
****************************************************/

/*
 * dna_fix_maxval()
 *
 * Attempts to extend the range represented by
 * config_entry.  If skip_range_request is set,
 * we will only attempt to activate the next
 * range.  No attempt will be made to transfer
 * range from another server.
 *
 * The lock for configEntry should be obtained
 * before calling this function.
 */
static int
dna_fix_maxval(struct configEntry *config_entry,
               int skip_range_request)
{
    PRCList *servers = NULL;
    PRCList *server = NULL;
    PRUint64 lower = 0;
    PRUint64 upper = 0;
    int ret = LDAP_OPERATIONS_ERROR;

    if (config_entry == NULL) {
        goto bail;
    }

    /* If we already have a next range we only need
     * to activate it. */
    if (config_entry->next_range_lower != 0) {
        ret = dna_activate_next_range(config_entry);
        if (ret != 0) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_fix_maxval - Unable to activate the "
                          "next range for range %s.\n",
                          config_entry->dn);
        }
    } else if (!skip_range_request && config_entry->shared_cfg_base) {
        /* Find out if there are any other servers to request
         * range from. */
        dna_get_shared_servers(config_entry, &servers, 0);

        if (servers) {
            /* We have other servers we can try to extend
             * our range from.  Loop through them and
             * request range until someone gives us some
             * values, or we hit the end of the list. */
            server = PR_LIST_HEAD(servers);
            while (server != servers) {
                if (((struct dnaServer *)server)->remaining == 0) {
                    /* This server has no values left, no need to ping it */
                    server = PR_NEXT_LINK(server);
                } else if (dna_request_range(config_entry, (struct dnaServer *)server,
                                             &lower, &upper) != 0) {
                    server = PR_NEXT_LINK(server);
                } else {
                    /* Someone provided us with a new range. Attempt
                     * to update the config. */
                    if ((ret = dna_update_next_range(config_entry, lower, upper)) == 0) {
                        break;
                    }
                    server = PR_NEXT_LINK(server);
                }
            }

            /* free the list of servers */
            dna_delete_shared_servers(&servers);
        }
    }

bail:
    return ret;
}

/* dna_notice_allocation()
 *
 * Called after a new value has been allocated from the range.
 * This function will update the config entries and cached info
 * appropriately.  This includes activating the next range if
 * we've exhausted the current range.
 *
 * The last parameter is the value that has just been allocated.
 * The new parameter should be the next available value. If you
 * set both of these parameters to 0, then this function will
 * just check if the next range needs to be activated and update
 * the config accordingly.
 *
 * The lock for configEntry should be obtained before calling
 * this function. */
static void
dna_notice_allocation(struct configEntry *config_entry, PRUint64 new, PRUint64 last)
{
    /* update our cached config entry */
    if ((new != 0) && (new <= (config_entry->maxval + config_entry->interval))) {
        config_entry->nextval = new;
    }

    /* check if we've exhausted our active range */
    if ((last == config_entry->maxval) ||
        (config_entry->nextval > config_entry->maxval)) {
        /* If we already have a next range set, make it the
         * new active range. */
        if (config_entry->next_range_lower != 0) {
            /* Make the next range active */
            if (dna_activate_next_range(config_entry) != 0) {
                slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                              "dna_notice_allocation - Unable to activate "
                              "the next range for range %s.\n",
                              config_entry->dn);
            }
        } else {
            config_entry->remaining = 0;
            /* update the shared configuration */
            dna_update_shared_config(config_entry);
        }
    } else {
        if (config_entry->next_range_lower != 0) {
            config_entry->remaining = ((config_entry->maxval - config_entry->nextval + 1) /
                                       config_entry->interval) +
                                      ((config_entry->next_range_upper -
                                        config_entry->next_range_lower + 1) /
                                       config_entry->interval);
        } else {
            config_entry->remaining = ((config_entry->maxval - config_entry->nextval + 1) /
                                       config_entry->interval);
        }

        /* update the shared configuration */
        dna_update_shared_config(config_entry);
    }

    return;
}

static int
dna_get_shared_servers(struct configEntry *config_entry, PRCList **servers, int get_all)
{
    int ret = LDAP_SUCCESS;
    Slapi_PBlock *pb = NULL;
    Slapi_Entry **entries = NULL;
    char *attrs[7];

    /* First do a search in the shared config area for this
     * range to find other servers who are managing this range. */
    attrs[0] = DNA_HOSTNAME;
    attrs[1] = DNA_PORTNUM;
    attrs[2] = DNA_SECURE_PORTNUM;
    attrs[3] = DNA_REMAINING;
    attrs[4] = DNA_REMOTE_BIND_METHOD;
    attrs[5] = DNA_REMOTE_CONN_PROT;
    attrs[6] = NULL;

    pb = slapi_pblock_new();
    if (NULL == pb) {
        ret = LDAP_OPERATIONS_ERROR;
        goto cleanup;
    }

    slapi_search_internal_set_pb(pb, config_entry->shared_cfg_base,
                                 LDAP_SCOPE_ONELEVEL, "objectclass=*",
                                 attrs, 0, NULL,
                                 NULL, getPluginID(), 0);
    slapi_search_internal_pb(pb);

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    if (LDAP_SUCCESS != ret) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_get_shared_servers - Search failed for shared "
                      "config: %s [error %d]\n",
                      config_entry->shared_cfg_base,
                      ret);
        goto cleanup;
    }

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                     &entries);

    if (entries && entries[0]) {
        Slapi_DN *cfg_sdn = NULL;
        int i;

        cfg_sdn = slapi_sdn_new_normdn_byref(config_entry->shared_cfg_dn);

        /* We found some entries.  Go through them and
         * order them based off of remaining values. */
        for (i = 0; entries[i]; i++) {
            /* skip our own shared config entry, unless we want all the servers */
            if (get_all || slapi_sdn_compare(cfg_sdn, slapi_entry_get_sdn(entries[i]))) {
                struct dnaServer *server = NULL;

                /* set up the server list entry */
                server = (struct dnaServer *)slapi_ch_calloc(1,
                                                             sizeof(struct dnaServer));
                server->sdn = slapi_sdn_new_dn_byval(slapi_entry_get_ndn(entries[i]));
                server->host = slapi_entry_attr_get_charptr(entries[i],
                                                            DNA_HOSTNAME);
                server->port = slapi_entry_attr_get_uint(entries[i], DNA_PORTNUM);
                server->secureport = slapi_entry_attr_get_uint(entries[i], DNA_SECURE_PORTNUM);
                server->remaining = slapi_entry_attr_get_ulonglong(entries[i],
                                                                   DNA_REMAINING);
                server->remote_binddn = config_entry->remote_binddn;
                server->remote_bindpw = config_entry->remote_bindpw;
                server->remote_bind_method = slapi_entry_attr_get_charptr(entries[i],
                                                                          DNA_REMOTE_BIND_METHOD);
                server->remote_conn_prot = slapi_entry_attr_get_charptr(entries[i],
                                                                        DNA_REMOTE_CONN_PROT);

                /* validate the entry */
                if (!server->host || (server->port == 0 && server->secureport == 0)) {
                    /* free and skip this one */
                    slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                                  "dna_get_shared_servers - Skipping invalid "
                                  "shared config entry (%s)\n",
                                  slapi_entry_get_dn(entries[i]));
                    dna_free_shared_server(&server);
                    continue;
                }
                /* see if we defined a server manually */
                if (server->remote_bind_method || server->remote_conn_prot) {
                    char *reason = NULL;
                    int err = 0;

                    if (server->remote_bind_method == NULL || server->remote_conn_prot == NULL) {
                        reason = "You must set both a bind method, and a connection protocol";
                        err = 1;
                        goto done;
                    }
                    if (strcasecmp(server->remote_bind_method, DNA_METHOD_DIGESTMD5) == 0 ||
                        strcasecmp(server->remote_bind_method, DNA_METHOD_SIMPLE) == 0)
                    {
                        /* requires a DN and password */
                        if (!server->remote_binddn || !server->remote_bindpw) {
                            reason = "missing bind DN and/or password.";
                            err = 1;
                            goto done;
                        }
                    }
                    if (strcasecmp(server->remote_bind_method, DNA_METHOD_SSL) == 0) {
                        /* requires a bind DN */
                        if ((strcasecmp(server->remote_conn_prot, DNA_PROT_SSL) != 0 ||
                             strcasecmp(server->remote_conn_prot, DNA_PROT_LDAPS) != 0) &&
                            (strcasecmp(server->remote_conn_prot, DNA_PROT_TLS) != 0 ||
                             strcasecmp(server->remote_conn_prot, DNA_PROT_STARTTLS) != 0))
                        {
                            reason = "bind method (SSL) requires either SSL or TLS connection protocol.";
                            err = 1;
                        }
                    }
done:
                    if (err) {
                        slapi_log_err(SLAPI_LOG_NOTICE, DNA_PLUGIN_SUBSYSTEM,
                                      "dna_get_shared_servers - Skipping invalid "
                                      "shared config entry (%s). Reason: %s\n",
                                      slapi_entry_get_dn(entries[i]), reason);
                        dna_free_shared_server(&server);
                        continue;
                    }
                    /* everything is ok */
                    server->remote_defined = 1;
                }

                /* add a server entry to the list */
                if (*servers == NULL) {
                    /* first entry */
                    *servers = (PRCList *)slapi_ch_calloc(1,
                                                          sizeof(struct dnaServer));
                    PR_INIT_CLIST(*servers);
                    PR_INSERT_LINK(&(server->list), *servers);
                } else {
                    /* Find the right slot for this entry. We
                     * want to order the entries based off of
                     * the remaining number of values, highest
                     * to lowest. */
                    struct dnaServer *sitem;
                    PRCList *item = PR_LIST_HEAD(*servers);
                    int inserted = 0;

                    while (item != *servers) {
                        sitem = (struct dnaServer *)item;
                        if (server->remaining > sitem->remaining) {
                            PR_INSERT_BEFORE(&(server->list), item);
                            inserted = 1;
                            break;
                        }

                        item = PR_NEXT_LINK(item);

                        if (*servers == item) {
                            /* add to tail */
                            PR_INSERT_BEFORE(&(server->list), item);
                            inserted = 1;
                            break;
                        }
                    }
                    if (!inserted) {
                        dna_free_shared_server(&server);
                    }
                }
            }
        }

        slapi_sdn_free(&cfg_sdn);
    }


cleanup:
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    return ret;
}

/*
 * dna_request_range()
 *
 * Requests range extension from another server.
 * Returns 0 on success and will fill in upper
 * and lower.  Returns non-0 on failure and will
 * zero out upper and lower.
 */
static int
dna_request_range(struct configEntry *config_entry,
                  struct dnaServer *server,
                  PRUint64 *lower,
                  PRUint64 *upper)
{
    char *bind_dn = NULL;
    char *bind_passwd = NULL;
    char *bind_method = NULL;
    int is_ssl = 0;
    struct berval *request = NULL;
    char *retoid = NULL;
    struct berval *responsedata = NULL;
    BerElement *respber = NULL;
    LDAP *ld = NULL;
    char *lower_str = NULL;
    char *upper_str = NULL;
    int set_extend_flag = 0;
    int ret = LDAP_OPERATIONS_ERROR;
    int port = 0;
    int timelimit;
    struct timeval timeout;
    /* See if we're allowed to send a range request now */
    slapi_lock_mutex(config_entry->extend_lock);
    if (config_entry->extend_in_progress) {
        /* We're already processing a range extention, so bail. */
        slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                      "dna_request_range - Already processing a "
                      "range extension request.  Skipping request.\n");
        slapi_unlock_mutex(config_entry->extend_lock);
        goto bail;
    } else {
        /* Set a flag indicating that we're attempting to extend this range */
        config_entry->extend_in_progress = 1;
        set_extend_flag = 1;
        slapi_unlock_mutex(config_entry->extend_lock);
    }

    /* Fetch the replication bind dn info */
    if (dna_get_replica_bind_creds(config_entry->shared_cfg_base, server,
                                   &bind_dn, &bind_passwd, &bind_method,
                                   &is_ssl, &port) != 0) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_request_range: Unable to retrieve "
                      "replica bind credentials.\n");
        goto bail;
    }

    if ((request = dna_create_range_request(config_entry->shared_cfg_base)) == NULL) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_request_range - Failed to create "
                      "range extension extended operation request.\n");
        goto bail;
    }

    if ((ld = slapi_ldap_init(server->host, port, is_ssl, 0)) == NULL) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_request_range - Unable to "
                      "initialize LDAP session to server %s:%u.\n",
                      server->host, server->port);
        goto bail;
    }

    /* Disable referrals and set timelimit and a connect timeout */
    ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    timelimit = config_entry->timeout / 1000; /* timeout is in msec */
    ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &timelimit);
    timeout.tv_sec = config_entry->timeout / 1000;
    timeout.tv_usec = (config_entry->timeout % 1000) * 1000;
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
    /* Bind to the replica server */
    ret = slapi_ldap_bind(ld, bind_dn, bind_passwd, bind_method,
                          NULL, NULL, NULL, NULL);

    if (ret != LDAP_SUCCESS) {
        slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                      "dna_request_range - Error binding "
                      " to replica server %s:%u. [error %d]\n",
                      server->host, server->port, ret);
        goto bail;
    }

    /* Send range extension request */
    ret = ldap_extended_operation_s(ld, DNA_EXTEND_EXOP_REQUEST_OID,
                                    request, NULL, NULL, &retoid, &responsedata);

    if (ret != LDAP_SUCCESS) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_request_range - Error sending "
                      "range extension extended operation request "
                      "to server %s:%u [error %d]\n",
                      server->host,
                      server->port, ret);
        goto bail;
    }

    /* Verify that the OID is correct. */
    if (strcmp(retoid, DNA_EXTEND_EXOP_RESPONSE_OID) != 0) {
        ret = LDAP_OPERATIONS_ERROR;
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_request_range - Received incorrect response OID.\n");
        goto bail;
    }

    /* Parse response */
    if (BV_HAS_DATA(responsedata)) {
        respber = ber_init(responsedata);
        if (ber_scanf(respber, "{aa}", &lower_str, &upper_str) == LBER_ERROR) {
            ret = LDAP_PROTOCOL_ERROR;
            goto bail;
        }
    }

    /* Fill in upper and lower */
    if (upper_str && lower_str) {
        *upper = strtoull(upper_str, 0, 0);
        *lower = strtoull(lower_str, 0, 0);
        ret = 0;
    } else {
        ret = LDAP_OPERATIONS_ERROR;
    }

bail:
    if (set_extend_flag) {
        slapi_lock_mutex(config_entry->extend_lock);
        config_entry->extend_in_progress = 0;
        slapi_unlock_mutex(config_entry->extend_lock);
    }
    slapi_ldap_unbind(ld);
    slapi_ch_free_string(&bind_dn);
    slapi_ch_free_string(&bind_passwd);
    slapi_ch_free_string(&bind_method);
    slapi_ch_free_string(&retoid);
    slapi_ch_free_string(&lower_str);
    slapi_ch_free_string(&upper_str);
    ber_free(respber, 1);
    ber_bvfree(request);
    ber_bvfree(responsedata);

    if (ret != 0) {
        *upper = 0;
        *lower = 0;
    }

    return ret;
}

static struct berval *
dna_create_range_request(char *range_dn)
{
    struct berval *requestdata = NULL;
    struct berval shared_dn = {0, NULL};
    BerElement *ber = NULL;

    shared_dn.bv_val = range_dn;
    shared_dn.bv_len = strlen(shared_dn.bv_val);

    if ((ber = ber_alloc()) == NULL) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_create_range_request - Error "
                      "allocating request data.\n");
        goto bail;
    }

    if (LBER_ERROR == (ber_printf(ber, "{o}", shared_dn.bv_val, shared_dn.bv_len))) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_create_range_request - Error "
                      "encoding request data.\n");
        goto bail;
    }

    if (ber_flatten(ber, &requestdata) == -1) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_create_range_request -  Error "
                      "encoding request data.\n");
        goto bail;
    }

bail:
    ber_free(ber, 1);

    return requestdata;
}

/****************************************************
    Helpers
****************************************************/

static char *
dna_get_dn(Slapi_PBlock *pb)
{
    Slapi_DN *sdn = 0;
    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_get_dn\n");

    if (slapi_pblock_get(pb, SLAPI_TARGET_SDN, &sdn)) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_get_dn - Failed to get dn of changed entry");
        goto bail;
    }

bail:
    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_get_dn\n");

    return (char *)slapi_sdn_get_dn(sdn);
}

/* config check
        matching config dn or a descendent reloads config
*/
static int
dna_dn_is_config(char *dn)
{
    int ret = 0;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_is_config %s\n", dn);

    if (slapi_dn_issuffix(dn, getPluginDN())) {
        ret = 1;
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_is_config\n");

    return ret;
}

static int
dna_dn_is_shared_config(Slapi_PBlock *pb, char *dn)
{
    struct configEntry *config_entry = NULL;
    Slapi_Entry *entry = NULL;
    Slapi_Attr *attr = NULL;
    PRCList *list = NULL;
    int ret = 0;

    dna_read_lock();
    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        list = PR_LIST_HEAD(dna_global_config);
        while (list != dna_global_config) {
            config_entry = (struct configEntry *)list;
            if (slapi_dn_issuffix(dn, config_entry->shared_cfg_base)) {
                slapi_pblock_get(pb, SLAPI_ENTRY_POST_OP, &entry);
                /* If the entry has the dnaHost attribute, it is a shared entry */
                if (slapi_entry_attr_find(entry, DNA_HOSTNAME, &attr) == 0) {
                    ret = 1;
                    break;
                }
            }
            list = PR_NEXT_LINK(list);
        }
    }
    dna_unlock();

    return ret;
}

#define DNA_LDAP_TAG_SK_REVERSE 0x81L

static LDAPControl *
dna_build_sort_control(const char *attr)
{
    LDAPControl *ctrl;
    BerElement *ber;
    int rc;

    ber = ber_alloc();
    if (NULL == ber)
        return NULL;

    rc = ber_printf(ber, "{{stb}}", attr, DNA_LDAP_TAG_SK_REVERSE, 1);
    if (-1 == rc) {
        ber_free(ber, 1);
        return NULL;
    }

    rc = slapi_build_control(LDAP_CONTROL_SORTREQUEST, ber, 1, &ctrl);

    ber_free(ber, 1);

    if (LDAP_SUCCESS != rc)
        return NULL;

    return ctrl;
}

/****************************************************
        Functions that actually do things other
        than config and startup
****************************************************/

/*
 * dna_first_free_value()
 *
 * We do search all values between nextval and maxval asking the
 * server to sort them, then we check the first free spot and
 * use it as newval.  If we go past the end of the range, we
 * return LDAP_OPERATIONS_ERROR and set newval to be > the
 * maximum configured value for this range. */
static int
dna_first_free_value(struct configEntry *config_entry,
                     PRUint64 *newval)
{
    Slapi_Entry **entries = NULL;
    Slapi_PBlock *pb = NULL;
    LDAPControl **ctrls = NULL;
    char *filter = NULL;
    char *prefix = NULL;
    int multitype = 0;
    int result, status;
    PRUint64 tmpval, sval, i;
    char *strval = NULL;

    /* check if the config is already out of range */
    if (config_entry->nextval > config_entry->maxval) {
        *newval = config_entry->nextval;
        return LDAP_OPERATIONS_ERROR;
    }

    prefix = config_entry->prefix;
    tmpval = config_entry->nextval;

    if (dna_is_multitype_range(config_entry)) {
        multitype = 1;
    }

    /* We don't sort if we're using a prefix (non integer type) or if this
     * is a multi-type range.  Instead, we just search to see if the next
     * value is free, and keep incrementing until we find the next free value. */
    if (prefix || multitype) {
        /* This will allocate the filter string for us. */
        dna_create_valcheck_filter(config_entry, tmpval, &filter);
    } else {
        /* This is a single-type range, so just use the first (only)
         * type from the list. */
        ctrls = (LDAPControl **)slapi_ch_calloc(2, sizeof(LDAPControl *));
        if (NULL == ctrls)
            return LDAP_OPERATIONS_ERROR;

        ctrls[0] = dna_build_sort_control(config_entry->types[0]);
        if (NULL == ctrls[0]) {
            slapi_ch_free((void **)&ctrls);
            return LDAP_OPERATIONS_ERROR;
        }

        filter = slapi_ch_smprintf("(&%s(&(%s>=%" PRIu64 ")(%s<=%" PRIu64 ")))",
                                   config_entry->filter,
                                   config_entry->types[0], tmpval,
                                   config_entry->types[0], config_entry->maxval);
    }

    if (NULL == filter) {
        ldap_controls_free(ctrls);
        ctrls = NULL;
        return LDAP_OPERATIONS_ERROR;
    }

    pb = slapi_pblock_new();
    if (NULL == pb) {
        ldap_controls_free(ctrls);
        ctrls = NULL;
        slapi_ch_free_string(&filter);
        return LDAP_OPERATIONS_ERROR;
    }

    slapi_search_internal_set_pb(pb, config_entry->scope,
                                 LDAP_SCOPE_SUBTREE, filter,
                                 config_entry->types, 0, ctrls,
                                 NULL, getPluginID(), 0);
    slapi_search_internal_pb(pb);

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &result);
    if (LDAP_SUCCESS != result) {
        status = LDAP_OPERATIONS_ERROR;
        goto cleanup;
    }

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                     &entries);

    if (NULL == entries || NULL == entries[0]) {
        /* no values means we already have a good value */
        *newval = tmpval;
        status = LDAP_SUCCESS;
        goto cleanup;
    }

    if (prefix || multitype) {
        /* The next value identified in the config entry has already
         * been taken.  We just iterate through the values until we
         * (hopefully) find a free one. */
        for (tmpval += config_entry->interval; tmpval <= config_entry->maxval;
             tmpval += config_entry->interval) {
            /* This will reuse the old memory for the previous filter.  It is
             * guaranteed to have enough space since the filter is the same
             * aside from the assertion value (we allocated enough for the
             * largest supported integer). */
            dna_create_valcheck_filter(config_entry, tmpval, &filter);

            /* clear out the pblock so we can re-use it */
            slapi_free_search_results_internal(pb);
            slapi_pblock_init(pb);

            slapi_search_internal_set_pb(pb, config_entry->scope,
                                         LDAP_SCOPE_SUBTREE, filter,
                                         config_entry->types, 0, 0,
                                         NULL, getPluginID(), 0);

            slapi_search_internal_pb(pb);

            slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &result);
            if (LDAP_SUCCESS != result) {
                status = LDAP_OPERATIONS_ERROR;
                goto cleanup;
            }

            slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                             &entries);

            if (NULL == entries || NULL == entries[0]) {
                /* no values means we already have a good value */
                *newval = tmpval;
                status = LDAP_SUCCESS;
                goto cleanup;
            }
        }
    } else {
        /* Entries are sorted and filtered for value >= tval therefore if the
         * first one does not match tval it means that the value is free,
         * otherwise we need to cycle through values until we find a mismatch,
         * the first mismatch is the first free pit.  This is guaranteed to
         * be a single-type range, so we can just use the first (only)
         * type from the list of types directly. */
        sval = 0;
        for (i = 0; NULL != entries[i]; i++) {
            strval = slapi_entry_attr_get_charptr(entries[i], config_entry->types[0]);
            errno = 0;
            sval = strtoull(strval, 0, 0);
            if (errno) {
                /* something very wrong here ... */
                status = LDAP_OPERATIONS_ERROR;
                goto cleanup;
            }
            slapi_ch_free_string(&strval);

            if (tmpval != sval)
                break;

            if (config_entry->maxval < sval)
                break;

            tmpval += config_entry->interval;
        }
    }

    /* check if we went past the end of the range */
    if (tmpval <= config_entry->maxval) {
        *newval = tmpval;
        status = LDAP_SUCCESS;
    } else {
        /* we set newval past the end of the range
         * so the caller can easily detect that we
         * overflowed the configured range. */
        *newval = tmpval;
        status = LDAP_OPERATIONS_ERROR;
    }

cleanup:
    slapi_ch_free_string(&filter);
    slapi_ch_free_string(&strval);
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);

    return status;
}

/*
 * Perform ldap operationally atomic increment
 * Return the next value to be assigned
 */
static int
dna_get_next_value(struct configEntry *config_entry,
                   char **next_value_ret)
{
    Slapi_PBlock *pb = NULL;
    LDAPMod mod_replace;
    LDAPMod *mods[2];
    char *replace_val[2];
    /* 16 for max 64-bit unsigned plus the trailing '\0' */
    char next_value[22] = {0};
    PRUint64 setval = 0;
    PRUint64 nextval = 0;
    int ret;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_get_next_value\n");

    /* get the lock to prevent contention with other threads over
     * the next new value for this range. */
    slapi_lock_mutex(config_entry->lock);

    /* get the first value */
    ret = dna_first_free_value(config_entry, &setval);
    if (LDAP_SUCCESS != ret) {
        /* check if we overflowed the configured range */
        if (setval > config_entry->maxval) {
            /* This should not happen, as pre_op should of allocated the next range.
             * In case this does occur, we will attempt to activate the next range if
             * one is available.  We tell dna_fix_maxval() to skip sending a range
             * transfer request, we we don't want to perform any network operations
             * while within a transaction. */
            ret = dna_fix_maxval(config_entry, 1 /* skip range transfer request */);
            if (LDAP_SUCCESS != ret) {
                slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                              "dna_get_next_value - No more values available!!\n");
                goto done;
            }

            /* get the first value from our newly extended range */
            ret = dna_first_free_value(config_entry, &setval);
            if (LDAP_SUCCESS != ret)
                goto done;
        } else {
            /* dna_first_free_value() failed for some unknown reason */
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_get_next_value - Failed to allocate a new ID!!\n");
            goto done;
        }
    }

    nextval = setval + config_entry->interval;
    /* update nextval if we have not reached the end
     * of our current range */
    if ((config_entry->maxval == -1) ||
        (nextval <= (config_entry->maxval + config_entry->interval))) {
        /* try to set the new next value in the config entry */
        snprintf(next_value, sizeof(next_value), "%" PRIu64, nextval);

        /* set up our replace modify operation */
        replace_val[0] = next_value;
        replace_val[1] = 0;
        mod_replace.mod_op = LDAP_MOD_REPLACE;
        mod_replace.mod_type = DNA_NEXTVAL;
        mod_replace.mod_values = replace_val;
        mods[0] = &mod_replace;
        mods[1] = 0;

        pb = slapi_pblock_new();
        if (NULL == pb) {
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        slapi_modify_internal_set_pb(pb, config_entry->dn,
                                     mods, 0, 0, getPluginID(), 0);

        slapi_modify_internal_pb(pb);

        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    }

    if (LDAP_SUCCESS == ret) {
        slapi_ch_free_string(next_value_ret);
        *next_value_ret = slapi_ch_smprintf("%" PRIu64, setval);
        if (NULL == *next_value_ret) {
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        /* update our cached config */
        dna_notice_allocation(config_entry, nextval, setval);
    }

done:
    slapi_unlock_mutex(config_entry->lock);

    if (pb) {
        slapi_pblock_destroy(pb);
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_get_next_value\n");

    return ret;
}

/*
 * Get a value from the global server list.  The dna_server_read_lock()
 * should be held prior to calling this function.
 */
static int
dna_get_shared_config_attr_val(struct configEntry *config_entry, char *attr, char *value)
{
    struct dnaServer *server = NULL;
    Slapi_DN *server_sdn = NULL;
    int found = 0;

    server_sdn = slapi_sdn_new_dn_byref(config_entry->shared_cfg_dn);
    if (dna_global_servers) {
        server = dna_global_servers;
        while (server) {
            if (slapi_sdn_compare(server->sdn, server_sdn) == 0) {
                if (strcmp(attr, DNA_REMOTE_BIND_METHOD) == 0) {
                    if (server->remote_bind_method) {
                        snprintf(value, DNA_REMOTE_BUFSIZ, "%s", server->remote_bind_method);
                        found = 1;
                    }
                    break;
                } else if (strcmp(attr, DNA_REMOTE_CONN_PROT) == 0) {
                    if (server->remote_conn_prot) {
                        snprintf(value, DNA_REMOTE_BUFSIZ, "%s", server->remote_conn_prot);
                        found = 1;
                    }
                    break;
                }
            }
            server = server->next;
        }
    }
    slapi_sdn_free(&server_sdn);

    return found;
}
/*
 * dna_update_shared_config()
 *
 * Updates the shared config entry if one is
 * configured.  Returns the LDAP result code.
 *
 * The lock for configEntry should be obtained
 * before calling this function.
 * */
static int
dna_update_shared_config(struct configEntry *config_entry)
{
    int ret = LDAP_SUCCESS;

    if (config_entry && config_entry->shared_cfg_dn) {
        /* Update the shared config entry if one is configured */
        Slapi_PBlock *pb = NULL;
        LDAPMod mod_replace;
        LDAPMod *mods[2];
        char *replace_val[2];
        /* 16 for max 64-bit unsigned plus the trailing '\0' */
        char remaining_vals[22];

        /* We store the number of remaining assigned values
         * in the shared config entry. */
        snprintf(remaining_vals, sizeof(remaining_vals), "%" PRIu64,
                 config_entry->remaining);

        /* set up our replace modify operation */
        replace_val[0] = remaining_vals;
        replace_val[1] = 0;
        mod_replace.mod_op = LDAP_MOD_REPLACE;
        mod_replace.mod_type = DNA_REMAINING;
        mod_replace.mod_values = replace_val;
        mods[0] = &mod_replace;
        mods[1] = 0;

        pb = slapi_pblock_new();
        if (NULL == pb) {
            ret = LDAP_OPERATIONS_ERROR;
        } else {
            slapi_modify_internal_set_pb(pb, config_entry->shared_cfg_dn,
                                         mods, NULL, NULL, getPluginID(), 0);

            slapi_modify_internal_pb(pb);

            slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

            /* If the shared config for this instance doesn't
             * already exist, we add it. */
            if (ret == LDAP_NO_SUCH_OBJECT) {
                Slapi_Entry *e = NULL;
                Slapi_DN *sdn = slapi_sdn_new_normdn_byref(config_entry->shared_cfg_dn);
                char bind_meth[DNA_REMOTE_BUFSIZ];
                char conn_prot[DNA_REMOTE_BUFSIZ];

                /* Set up the new shared config entry */
                e = slapi_entry_alloc();
                /* the entry now owns the dup'd dn */
                slapi_entry_init_ext(e, sdn, NULL); /* sdn is copied into e */
                slapi_sdn_free(&sdn);

                slapi_entry_add_string(e, SLAPI_ATTR_OBJECTCLASS, DNA_SHAREDCONFIG);
                slapi_entry_add_string(e, DNA_HOSTNAME, hostname);
                slapi_entry_add_string(e, DNA_PORTNUM, portnum);
                if (secureportnum) {
                    slapi_entry_add_string(e, DNA_SECURE_PORTNUM, secureportnum);
                }
                slapi_entry_add_string(e, DNA_REMAINING, remaining_vals);

                /* Grab the remote server settings */
                dna_server_read_lock();
                if (dna_get_shared_config_attr_val(config_entry, DNA_REMOTE_BIND_METHOD, bind_meth)) {
                    slapi_entry_add_string(e, DNA_REMOTE_BIND_METHOD, bind_meth);
                }
                if (dna_get_shared_config_attr_val(config_entry, DNA_REMOTE_CONN_PROT, conn_prot)) {
                    slapi_entry_add_string(e, DNA_REMOTE_CONN_PROT, conn_prot);
                }
                dna_server_unlock();

                /* clear pb for re-use */
                slapi_pblock_init(pb);

                /* e will be consumed by slapi_add_internal() */
                slapi_add_entry_internal_set_pb(pb, e, NULL, getPluginID(), 0);
                slapi_add_internal_pb(pb);
                slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
            }

            if (ret != LDAP_SUCCESS) {
                slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                              "dna_update_shared_config - Unable to update shared config entry: %s [error %d]\n",
                              config_entry->shared_cfg_dn, ret);
            }

            slapi_pblock_destroy(pb);
            pb = NULL;
        }
    }

    return ret;
}

/*
 * dna_update_next_range()
 *
 * Sets the proper value for the next range in
 * all configuration entries and in-memory cache.
 *
 * The range you are updating should be locked
 * before calling this function.
 */
static int
dna_update_next_range(struct configEntry *config_entry,
                      PRUint64 lower,
                      PRUint64 upper)
{
    Slapi_PBlock *pb = NULL;
    LDAPMod mod_replace;
    LDAPMod *mods[2];
    char *replace_val[2];
    /* 32 for the two numbers, 1 for the '-', and one for the '\0' */
    char nextrange_value[44];
    int ret = 0;

    /* Try to set the new next range in the config entry. */
    snprintf(nextrange_value, sizeof(nextrange_value), "%" PRIu64 "-%" PRIu64,
             lower, upper);

    /* set up our replace modify operation */
    replace_val[0] = nextrange_value;
    replace_val[1] = 0;
    mod_replace.mod_op = LDAP_MOD_REPLACE;
    mod_replace.mod_type = DNA_NEXT_RANGE;
    mod_replace.mod_values = replace_val;
    mods[0] = &mod_replace;
    mods[1] = 0;

    pb = slapi_pblock_new();
    if (NULL == pb) {
        ret = LDAP_OPERATIONS_ERROR;
        goto bail;
    }

    slapi_modify_internal_set_pb(pb, config_entry->dn,
                                 mods, 0, 0, getPluginID(), 0);

    slapi_modify_internal_pb(pb);

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

    slapi_pblock_destroy(pb);
    pb = NULL;

    if (ret != LDAP_SUCCESS) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_update_next_range - Error updating "
                      "configuration entry [err=%d]\n",
                      ret);
    } else {
        /* update the cached config and the shared config */
        config_entry->next_range_lower = lower;
        config_entry->next_range_upper = upper;
        dna_notice_allocation(config_entry, 0, 0);
    }

bail:
    return ret;
}

/* dna_activate_next_range()
 *
 * Makes the next range the active range.  This
 * will update the config entry, the in-memory
 * config info, and the shared config entry.
 *
 * The lock for configEntry should
 * be obtained before calling this function.
 */
static int
dna_activate_next_range(struct configEntry *config_entry)
{
    Slapi_PBlock *pb = NULL;
    LDAPMod mod_maxval;
    LDAPMod mod_nextval;
    LDAPMod mod_nextrange;
    LDAPMod *mods[4];
    char *maxval_vals[2];
    char *nextval_vals[2];
    char *nextrange_vals[1];
    /* 16 for max 64-bit unsigned plus the trailing '\0' */
    char maxval_val[22];
    char nextval_val[22];
    int ret = 0;

    /* Setup the modify operation for the config entry */
    snprintf(maxval_val, sizeof(maxval_val), "%" PRIu64, config_entry->next_range_upper);
    snprintf(nextval_val, sizeof(nextval_val), "%" PRIu64, config_entry->next_range_lower);

    maxval_vals[0] = maxval_val;
    maxval_vals[1] = 0;
    nextval_vals[0] = nextval_val;
    nextval_vals[1] = 0;
    nextrange_vals[0] = 0;

    mod_maxval.mod_op = LDAP_MOD_REPLACE;
    mod_maxval.mod_type = DNA_MAXVAL;
    mod_maxval.mod_values = maxval_vals;
    mod_nextval.mod_op = LDAP_MOD_REPLACE;
    mod_nextval.mod_type = DNA_NEXTVAL;
    mod_nextval.mod_values = nextval_vals;
    mod_nextrange.mod_op = LDAP_MOD_DELETE;
    mod_nextrange.mod_type = DNA_NEXT_RANGE;
    mod_nextrange.mod_values = nextrange_vals;

    mods[0] = &mod_maxval;
    mods[1] = &mod_nextval;
    mods[2] = &mod_nextrange;
    mods[3] = 0;

    /* Update the config entry first */
    pb = slapi_pblock_new();
    if (NULL == pb) {
        ret = LDAP_OPERATIONS_ERROR;
        goto bail;
    }

    slapi_modify_internal_set_pb(pb, config_entry->dn,
                                 mods, 0, 0, getPluginID(), 0);

    slapi_modify_internal_pb(pb);

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

    slapi_pblock_destroy(pb);
    pb = NULL;

    if (ret != LDAP_SUCCESS) {
        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                      "dna_activate_next_range - Error updating "
                      "configuration entry [err=%d]\n",
                      ret);
    } else {
        /* Update the in-memory config info */
        config_entry->maxval = config_entry->next_range_upper;
        config_entry->nextval = config_entry->next_range_lower;
        config_entry->next_range_upper = 0;
        config_entry->next_range_lower = 0;
        config_entry->remaining = ((config_entry->maxval - config_entry->nextval + 1) /
                                   config_entry->interval);
        /* update the shared configuration */
        dna_update_shared_config(config_entry);
    }

bail:
    return ret;
}

/*
 * dna_is_replica_bind_dn()
 *
 * Checks if the passed in DN is the replica bind DN.  This
 * is used to check if a user is allowed to request range
 * from us.
 *
 * Returns 1 if bind_dn matches the replica bind dn, 0 otherwise. */
static int
dna_is_replica_bind_dn(char *range_dn, char *bind_dn)
{
    Slapi_PBlock *entry_pb = NULL;
    char *replica_dn = NULL;
    Slapi_DN *replica_sdn = NULL;
    Slapi_DN *range_sdn = NULL;
    Slapi_Entry *e = NULL;
    char *attrs[3];
    Slapi_Backend *be = NULL;
    const char *be_suffix = NULL;
    int ret = 0;

    /* Find the backend suffix where the shared config is stored. */
    range_sdn = slapi_sdn_new_dn_byref(range_dn);
    if ((be = slapi_be_select(range_sdn)) != NULL) {
        be_suffix = slapi_sdn_get_dn(slapi_be_getsuffix(be, 0));
    }

    /* Fetch the "cn=replica" entry for the backend that stores
     * the shared config.  We need to see what the configured
     * replica bind DN is or if a bind DN group is defined. */
    if (be_suffix) {
        /* This function converts the old DN style to the new one. */
        replica_dn = slapi_create_dn_string("cn=replica,cn=\"%s\",cn=mapping tree,cn=config", be_suffix);
        if (NULL == replica_dn) {
            slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                          "dna_is_replica_bind_dn - Failed to create "
                          "replica dn for %s\n",
                          be_suffix);
            ret = 1;
            goto done;
        }
        replica_sdn = slapi_sdn_new_normdn_passin(replica_dn);

        attrs[0] = DNA_REPL_BIND_DN;
        attrs[1] = DNA_REPL_BIND_DNGROUP;
        attrs[2] = 0;

        /* Find cn=replica entry via search */
        slapi_search_get_entry(&entry_pb, replica_sdn, attrs, &e, getPluginID());
        if (e) {
            /* Check if the passed in bind dn matches any of the replica bind dns. */
            Slapi_Value *bind_dn_sv = slapi_value_new_string(bind_dn);
            ret = slapi_entry_attr_has_syntax_value(e, DNA_REPL_BIND_DN, bind_dn_sv);
            if (ret == 0) {
                /* check if binddn is member of binddn group */
                int i = 0;
                Slapi_DN *bind_group_sdn = NULL;
                Slapi_Entry *bind_group_entry = NULL;
                char **bind_group_dn = slapi_entry_attr_get_charray(e, DNA_REPL_BIND_DNGROUP);
                attrs[0] = "member";
                attrs[1] = "uniquemember";
                attrs[2] = 0;
                slapi_search_get_entry_done(&entry_pb);
                for (i = 0; bind_group_dn != NULL && bind_group_dn[i] != NULL; i++) {
                    if (ret) {
                        /* already found a member, just free group */
                        slapi_ch_free_string(&bind_group_dn[i]);
                        continue;
                    }
                    bind_group_sdn = slapi_sdn_new_normdn_passin(bind_group_dn[i]);
                    slapi_search_get_entry(&entry_pb, bind_group_sdn, attrs, &bind_group_entry, getPluginID());
                    if (bind_group_entry) {
                        ret = slapi_entry_attr_has_syntax_value(bind_group_entry, "member", bind_dn_sv);
                        if (ret == 0) {
                            ret = slapi_entry_attr_has_syntax_value(bind_group_entry, "uniquemember", bind_dn_sv);
                        }
                    }
                    slapi_search_get_entry_done(&entry_pb);
                    slapi_sdn_free(&bind_group_sdn);
                }
                slapi_ch_free((void **)&bind_group_dn);
            }
            slapi_value_free(&bind_dn_sv);
        } else {
            slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                          "dna_is_replica_bind_dn - Failed to fetch replica entry "
                          "for range %s\n",
                          range_dn);
        }
    }

done:
    slapi_sdn_free(&range_sdn);
    slapi_sdn_free(&replica_sdn);

    return ret;
}

static int
dna_get_replica_bind_creds(char *range_dn, struct dnaServer *server, char **bind_dn, char **bind_passwd, char **bind_method, int *is_ssl, int *port)
{
    Slapi_PBlock *pb = NULL;
    Slapi_DN *range_sdn = NULL;
    char *replica_dn = NULL;
    Slapi_Backend *be = NULL;
    const char *be_suffix = NULL;
    char *attrs[6];
    char *filter = NULL;
    char *bind_cred = NULL;
    char *transport = NULL;
    Slapi_Entry **entries = NULL;
    int ret = LDAP_OPERATIONS_ERROR;

    /* Find the backend suffix where the shared config is stored. */
    range_sdn = slapi_sdn_new_normdn_byref(range_dn);
    if ((be = slapi_be_select(range_sdn)) != NULL) {
        be_suffix = slapi_sdn_get_dn(slapi_be_getsuffix(be, 0));
    }

    /* Fetch the replication agreement entry */
    if (be_suffix) {
        /* This function converts the old DN style to the new one. */
        replica_dn = slapi_create_dn_string("cn=replica,cn=\"%s\",cn=mapping tree,cn=config", be_suffix);
        if (NULL == replica_dn) {
            slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                          "dna_get_replica_bind_creds - Failed to create "
                          "replica dn for %s\n",
                          be_suffix);
            ret = LDAP_PARAM_ERROR;
            goto bail;
        }

        filter = slapi_ch_smprintf("(&(nsds5ReplicaHost=%s)(|(" DNA_REPL_PORT "=%u)"
                                   "(" DNA_REPL_PORT "=%u)))",
                                   server->host, server->port, server->secureport);

        attrs[0] = DNA_REPL_BIND_DN;
        attrs[1] = DNA_REPL_CREDS;
        attrs[2] = DNA_REPL_BIND_METHOD;
        attrs[3] = DNA_REPL_TRANSPORT;
        attrs[4] = DNA_REPL_PORT;
        attrs[5] = 0;

        pb = slapi_pblock_new();
        if (NULL == pb) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_get_replica_bind_creds - Failed to "
                          "allocate pblock\n");
            goto bail;
        }

        slapi_search_internal_set_pb(pb, replica_dn,
                                     LDAP_SCOPE_ONELEVEL, filter,
                                     attrs, 0, NULL, NULL, getPluginID(), 0);
        slapi_search_internal_pb(pb);
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

        if (LDAP_SUCCESS != ret) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_get_replica_bind_creds - Failed to fetch replica "
                          "bind credentials for range %s, server %s, port %u [error %d]\n",
                          range_dn, server->host,
                          server->port ? server->port : server->secureport, ret);
            goto bail;
        }

        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                         &entries);

        if (NULL == entries || NULL == entries[0]) {
            if (server->remote_defined) {
                /*
                 * Ok there are no replication agreements for this shared server, but we
                 * do have custom defined authentication settings we can use.
                 */
                ret = dna_get_remote_config_info(server, bind_dn, bind_passwd, bind_method, is_ssl, port);
                goto bail;
            }
            slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                          "dna_get_replica_bind_creds - Failed to fetch replication "
                          "agreement for range %s, server %s, port %u\n",
                          range_dn,
                          server->host, server->port ? server->port : server->secureport);
            ret = LDAP_OPERATIONS_ERROR;
            goto bail;
        }

        /* Get the replication bind dn and password from the agreement.  It
         * is up to the caller to free these when they are finished. */
        slapi_ch_free_string(bind_dn);
        slapi_ch_free_string(bind_method);
        *bind_dn = slapi_entry_attr_get_charptr(entries[0], DNA_REPL_BIND_DN);
        *bind_method = slapi_entry_attr_get_charptr(entries[0], DNA_REPL_BIND_METHOD);
        bind_cred = slapi_entry_attr_get_charptr(entries[0], DNA_REPL_CREDS);
        transport = slapi_entry_attr_get_charptr(entries[0], DNA_REPL_TRANSPORT);
        *port = slapi_entry_attr_get_int(entries[0], DNA_REPL_PORT);

        /* Check if we should use SSL */
        if (transport && (strcasecmp(transport, DNA_PROT_SSL) == 0 || strcasecmp(transport, DNA_PROT_LDAPS) == 0)) {
            *is_ssl = 1;
        } else if (transport && (strcasecmp(transport, DNA_PROT_TLS) == 0 || strcasecmp(transport, DNA_PROT_STARTTLS) == 0))  {
            *is_ssl = 2;
        } else {
            *is_ssl = 0;
        }

        /* fix up the bind method */
        if ((NULL == *bind_method) || (strcasecmp(*bind_method, "SIMPLE") == 0)) {
            slapi_ch_free_string(bind_method);
            *bind_method = slapi_ch_strdup(LDAP_SASL_SIMPLE);
        } else if (strcasecmp(*bind_method, "SSLCLIENTAUTH") == 0) {
            slapi_ch_free_string(bind_method);
            *bind_method = slapi_ch_strdup(LDAP_SASL_EXTERNAL);
        } else if (strcasecmp(*bind_method, "SASL/GSSAPI") == 0) {
            slapi_ch_free_string(bind_method);
            *bind_method = slapi_ch_strdup("GSSAPI");
        } else if (strcasecmp(*bind_method, "SASL/DIGEST-MD5") == 0) {
            slapi_ch_free_string(bind_method);
            *bind_method = slapi_ch_strdup("DIGEST-MD5");
        } else { /* some other weird value */
            ;    /* just use it directly */
        }

        /* Decode the password */
        if (bind_cred) {
            int pw_ret = 0;
            slapi_ch_free_string(bind_passwd);
            pw_ret = pw_rever_decode(bind_cred, bind_passwd, DNA_REPL_CREDS);

            if (pw_ret == -1) {
                slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                              "dna_get_replica_bind_creds - Failed to decode "
                              "replica bind credentials for range %s, server %s, "
                              "port %u\n",
                              range_dn, server->host, server->port);
                goto bail;
            } else if (pw_ret != 0) {
                /* The password was already in clear text, so pw_rever_decode
                 * simply set bind_passwd to bind_cred.  Set bind_cred to NULL
                 * to prevent a double free.  The memory is now owned by
                 * bind_passwd, which is the callers responsibility to free. */
                bind_cred = NULL;
            }
        }
    }

    /* If we got here, we succesfully got the
     * creds.  Set the success return value. */
    ret = 0;

bail:
    slapi_ch_free_string(&transport);
    slapi_ch_free_string(&filter);
    slapi_sdn_free(&range_sdn);
    slapi_ch_free_string(&replica_dn);
    slapi_ch_free_string(&bind_cred);
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);

    return ret;
}

static int
dna_get_remote_config_info(struct dnaServer *server, char **bind_dn, char **bind_passwd, char **bind_method, int *is_ssl, int *port)
{
    int rc = 0;

    /* populate the bind info */
    slapi_ch_free_string(bind_dn);
    slapi_ch_free_string(bind_method);
    *bind_dn = slapi_ch_strdup(server->remote_binddn);
    *bind_method = slapi_ch_strdup(server->remote_bind_method);
    /* fix up the bind method */
    if ((NULL == *bind_method) || (strcasecmp(*bind_method, DNA_METHOD_SIMPLE) == 0)) {
        slapi_ch_free_string(bind_method);
        *bind_method = slapi_ch_strdup(LDAP_SASL_SIMPLE);
    } else if (strcasecmp(*bind_method, "SSLCLIENTAUTH") == 0) {
        slapi_ch_free_string(bind_method);
        *bind_method = slapi_ch_strdup(LDAP_SASL_EXTERNAL);
    } else if (strcasecmp(*bind_method, DNA_METHOD_GSSAPI) == 0) {
        slapi_ch_free_string(bind_method);
        *bind_method = slapi_ch_strdup("GSSAPI");
    } else if (strcasecmp(*bind_method, DNA_METHOD_DIGESTMD5) == 0) {
        slapi_ch_free_string(bind_method);
        *bind_method = slapi_ch_strdup("DIGEST-MD5");
    } else { /* some other weird value */
        ;    /* just use it directly */
    }

    if (server->remote_conn_prot && (strcasecmp(server->remote_conn_prot, DNA_PROT_SSL) == 0 ||
        strcasecmp(server->remote_conn_prot, DNA_PROT_LDAPS) == 0 )) {
        *is_ssl = 1;
    } else if (server->remote_conn_prot && (strcasecmp(server->remote_conn_prot, DNA_PROT_TLS) == 0 ||
               strcasecmp(server->remote_conn_prot, DNA_PROT_STARTTLS) == 0 )) {
        *is_ssl = 2;
    } else {
        *is_ssl = 0;
    }
    if (*is_ssl == 1) { /* SSL(covers TLS over ssl) */
        if (server->secureport) {
            *port = server->secureport;
        } else {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_get_remote_config_info - Using SSL protocol, but the secure "
                          "port is not defined.\n");
            return -1;
        }
    } else { /* LDAP/TLS(non secure port) */
        if (server->port) {
            *port = server->port;
        } else {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_get_remote_config_info - Using %s protocol, but the non-secure "
                          "port is not defined.\n",
                          server->remote_conn_prot);
            return -1;
        }
    }

    /* Decode the password */
    if (server->remote_bindpw) {
        char *bind_cred = slapi_ch_strdup(server->remote_bindpw);
        int pw_ret = 0;

        slapi_ch_free_string(bind_passwd);
        pw_ret = pw_rever_decode(bind_cred, bind_passwd, DNA_REPL_CREDS);

        if (pw_ret == -1) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_get_remote_config_info - Failed to decode "
                          "replica bind credentials for server %s, "
                          "port %u\n",
                          server->host,
                          server->port ? server->port : server->secureport);
            rc = -1;
        } else if (pw_ret != 0) {
            /*
             * The password was already in clear text, so pw_rever_decode
             * simply set bind_passwd to bind_cred.  Set bind_cred to NULL
             * to prevent a double free.  The memory is now owned by
             * bind_passwd, which is the callers responsibility to free.
             */
            bind_cred = NULL;
        }
        slapi_ch_free_string(&bind_cred);
    }

    return rc;
}


/*
 * dna_list_contains_type()
 *
 * Checks if a type is contained in a list of types.
 * Returns 1 if the type is found, 0 otherwise.
 */
static int
dna_list_contains_type(char **list, char *type)
{
    int ret = 0;
    int i = 0;

    if (list && type) {
        for (i = 0; list[i]; i++) {
            if (slapi_attr_types_equivalent(type, list[i])) {
                ret = 1;
                break;
            }
        }
    }

    return ret;
}

/*
 * dna_list_contains_types()
 *
 * Checks if all types in one list (types) are contained
 * in another list of types (list).  Returns 1 if all
 * types are found, 0 otherwise.
 */
static int
dna_list_contains_types(char **list, char **types)
{
    int ret = 1;
    int i = 0;
    int j = 0;

    if (list && types) {
        for (i = 0; types[i]; i++) {
            int found = 0;

            for (j = 0; list[j]; j++) {
                if (slapi_attr_types_equivalent(types[i], list[i])) {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                ret = 0;
                break;
            }
        }
    } else {
        ret = 0;
    }

    return ret;
}

/*
 * dna_list_remove_type()
 *
 * Removes a type from a list of types.
 */
static void
dna_list_remove_type(char **list, char *type)
{
    int i = 0;
    int found_type = 0;

    if (list && type) {
        /* Go through the list until we find the type that
         * we want to remove.  We simply free the type we
         * want to remove and shift the remaining array
         * elements down by one index.  This will leave us
         * with two NULL elements at the end of the list,
         * but this should not cause any problems. */
        for (i = 0; list[i]; i++) {
            if (found_type) {
                list[i] = list[i + 1];
            } else if (slapi_attr_types_equivalent(type, list[i])) {
                slapi_ch_free_string(&list[i]);
                list[i] = list[i + 1];
                found_type = 1;
            }
        }
    }
}

/*
 * dna_is_multitype_range()
 *
 * Returns 1 if the range has multiple types configured.
 * Returns 0 otherwise.
 */
static int
dna_is_multitype_range(struct configEntry *config_entry)
{
    int ret = 0;

    if (config_entry && config_entry->types && config_entry->types[1]) {
        ret = 1;
    }

    return ret;
}

/*
 * dna_create_valcheck_filter()
 *
 * Creates a filter string used to check if a value is free.  If
 * filter already holds a valid pointer, it is assumed to have enough
 * space to hold the filter.  This allows the same memory to be used
 * over and over when you only want to change the assertion value.
 * If filter contains a NULL pointer, a new string of the appropriate
 * size will be allocated.  The caller must free this when finished.
 */
static void
dna_create_valcheck_filter(struct configEntry *config_entry, PRUint64 value, char **filter)
{
    int filterlen = 0;
    int typeslen = 0;
    int i = 0;
    int bytes_out = 0;
    int multitype = 0;

    /* Just return if we didn't get an address for the filter. */
    if (filter == NULL) {
        return;
    }

    /* To determine the filter length, we add together the following:
     *
     * - the string length of the filter in the config
     * - the string length sum of all configured types
     * - 23 bytes for each type (20 for the max string
     *   representation of a PRIu64, 3 for "(=)"
     * - 3 bytes for the beginning and end of the filter - "(&" and ")"
     * - 3 bytes to OR together multiple types (if present) - "(|" and ")"
     * - the string length of the prefix (if one is configured) for each type
     * - 1 byte for the trailing \0
     *
     *   The filter length should be the same every time if the config struct
     *   has not been changed.  We need to calculate the filter length even
     *   if we are reusing memory since we have no other way of knowing the
     *   length used when it was originally allocated.  We trust the caller
     *   to only reuse the pointer with the same config struct.
     */
    for (i = 0; config_entry->types && config_entry->types[i]; i++) {
        typeslen += strlen(config_entry->types[i]);
    }

    if (i > 1) {
        multitype = 1;
    }

    filterlen = strlen(config_entry->filter) + typeslen +
                (i * 23) + 3 + 1 +
                (config_entry->prefix ? (i * strlen(config_entry->prefix)) : 0) +
                (multitype ? 3 : 0);

    /* Allocate space for the filter if it hasn't been allocated yet. */
    if (*filter == NULL) {
        *filter = slapi_ch_malloc(filterlen);
    }

    /* Write out the beginning of the filter.  If multiple types
     * are configured, we need to OR together the search clauses
     * for the types. */
    if (multitype) {
        bytes_out = snprintf(*filter, filterlen, "(&%s(|", config_entry->filter);
    } else {
        bytes_out = snprintf(*filter, filterlen, "(&%s", config_entry->filter);
    }

    /* Loop through the types and append each filter clause. */
    for (i = 0; config_entry->types && config_entry->types[i]; i++) {
        bytes_out += snprintf(*filter + bytes_out, filterlen - bytes_out,
                              "(%s=%s%" PRIu64 ")", config_entry->types[i],
                              config_entry->prefix ? config_entry->prefix : "",
                              value);
    }

    /* Append the end of the filter.  We need an extra paren
     * to close out the OR if we have multiple types. */
    if (multitype) {
        strncat(*filter, "))", filterlen - bytes_out);
    } else {
        strncat(*filter, ")", filterlen - bytes_out);
    }
}

/* This function is called at BEPREOP timing to add uid/gidNumber
 * if modtype is missing */
static int
_dna_pre_op_add(Slapi_PBlock *pb, Slapi_Entry *e, char **errstr)
{
    int ret = DNA_SUCCESS;
    PRCList *list = NULL;
    struct configEntry *config_entry = NULL;
    char *dn = NULL;
    char *value = NULL;
    char **types_to_generate = NULL;
    char **generated_types = NULL;
    PRUint64 setval = 0;
    int i;

    if (0 == (dn = dna_get_dn(pb))) {
        goto bail;
    }
    /*
     *  Find the config that matches this entry, Set the types that need to be
     *  generated to DNA_NEEDS_UPDATE.  The be_txn_preop will set the values if
     *  the operation hasn't been rejected by that point.
     *
     *  We also check if we need to get the next range of values, and grab them.
     *  We do this here so we don't have to do it in the be_txn_preop.
     */
    dna_read_lock();

    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        list = PR_LIST_HEAD(dna_global_config);

        while (list != dna_global_config && LDAP_SUCCESS == ret) {
            config_entry = (struct configEntry *)list;

            /* Did we already service all of these configured types? */
            if (dna_list_contains_types(generated_types, config_entry->types)) {
                slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM, "_dna_pre_op_add - No types to act upon.\n");
                goto next;
            }

            /* is the entry in scope? */
            if (config_entry->scope &&
                !slapi_dn_issuffix(dn, config_entry->scope)) {
                slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM, "    dn not in scope\n");
                goto next;
            }

            /* is this entry in an excluded scope? */
            for (i = 0; config_entry->excludescope && config_entry->excludescope[i]; i++) {
                if (slapi_dn_issuffix(dn, slapi_sdn_get_dn(config_entry->excludescope[i]))) {
                    slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM, "_dna_pre_op_add - dn in excluded scope\n");
                    goto next;
                }
            }

            /* does the entry match the filter? */
            if (config_entry->slapi_filter) {
                ret = slapi_vattr_filter_test(pb, e, config_entry->slapi_filter, 0);
                if (LDAP_SUCCESS != ret) {
                    slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM, "_dna_pre_op_add - dn does not match filter\n");
                    goto next;
                }
            }

            if (dna_is_multitype_range(config_entry)) {
                /* For a multi-type range, we only generate a value
                 * for types where the magic value is set.  We do not
                 * generate a value for missing types. */
                for (i = 0; config_entry->types && config_entry->types[i]; i++) {
                    value = slapi_entry_attr_get_charptr(e, config_entry->types[i]);
                    if (value) {
                        if (config_entry->generate == NULL || !slapi_UTF8CASECMP(config_entry->generate, value)) {
                            slapi_ch_array_add(&types_to_generate, slapi_ch_strdup(config_entry->types[i]));
                        }
                        slapi_ch_free_string(&value);
                    }
                }
            } else {
                /* For a single type range, we generate the value if
                 * the magic value is set or if the type is missing. */
                value = slapi_entry_attr_get_charptr(e, config_entry->types[0]);

                if ((config_entry->generate == NULL) || (0 == value) ||
                    (value && !slapi_UTF8CASECMP(config_entry->generate, value))) {
                    slapi_ch_array_add(&types_to_generate, slapi_ch_strdup(config_entry->types[0]));
                }
                slapi_ch_free_string(&value);
            }

            if (types_to_generate && types_to_generate[0]) {

                slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM, "_dna_pre_op_add - adding %s to %s as -2\n", types_to_generate[0], dn);
                /* add - add to entry */
                for (i = 0; types_to_generate && types_to_generate[i]; i++) {
                    slapi_entry_attr_set_charptr(e, types_to_generate[i],
                                                 /* no need to dup */
                                                 DNA_NEEDS_UPDATE);
                }
                /* Update the internalModifiersname for this add op */
                add_internal_modifiersname(pb, e);

                /* Make sure we don't generate for this
                 * type again by keeping a list of types
                 * we have generated for already.
                 */
                if (generated_types == NULL) {
                    /* If we don't have a list of generated types yet,
                     * we can just use the types_to_generate list so
                     * we don't have to allocate anything. */
                    generated_types = types_to_generate;
                    types_to_generate = NULL;
                } else {
                    /* Just reuse the elements out of types_to_generate for the
                     * generated types list to avoid allocating them again. */
                    for (i = 0; types_to_generate && types_to_generate[i]; ++i) {
                        slapi_ch_array_add(&generated_types, types_to_generate[i]);
                        types_to_generate[i] = NULL;
                    }
                }

                /* free up */
                slapi_ch_array_free(types_to_generate);
                types_to_generate = NULL;

                /*
                 *  Now grab the next value and see if we need to get the next range
                 */
                slapi_lock_mutex(config_entry->lock);

                ret = dna_first_free_value(config_entry, &setval);
                slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM, "_dna_pre_op_add - retrieved value %" PRIu64 " ret %d\n", setval, ret);
                if (LDAP_SUCCESS != ret) {
                    /* check if we overflowed the configured range */
                    if (setval > config_entry->maxval) {
                        /* try for a new range or fail */
                        ret = dna_fix_maxval(config_entry, 0);
                        if (LDAP_SUCCESS != ret) {
                            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                                          "_dna_pre_op_add - No more values available!!\n");
                            /* Set an error string to be returned to the client. */
                            *errstr = slapi_ch_smprintf("Allocation of a new value for range"
                                                        " %s failed! Unable to proceed.",
                                                        config_entry->dn);
                            slapi_unlock_mutex(config_entry->lock);
                            break;
                        }

                        /* Make sure dna_first_free_value() doesn't error out */
                        ret = dna_first_free_value(config_entry, &setval);
                        if (LDAP_SUCCESS != ret) {
                            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                                          "_dna_pre_op_add - Failed to allocate a new ID 1\n");
                            /* Set an error string to be returned to the client. */
                            *errstr = slapi_ch_smprintf("Allocation of a new value for range"
                                                        " %s failed! Unable to proceed.",
                                                        config_entry->dn);
                            slapi_unlock_mutex(config_entry->lock);
                            break;
                        }
                    } else {
                        /* dna_first_free_value() failed for some unknown reason */
                        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                                      "_dna_pre_op_add - Failed to allocate a new ID!! 2\n");
                        /* Set an error string to be returned to the client. */
                        *errstr = slapi_ch_smprintf("Allocation of a new value for range"
                                                    " %s failed! Unable to proceed.",
                                                    config_entry->dn);
                        slapi_unlock_mutex(config_entry->lock);
                        break;
                    }
                }

                /* Check if we passed the threshold and try to fix maxval if so.
                 * We don't need to do this if we already have a next range on
                 * deck.  We don't check the result of dna_fix_maxval() since
                 * we aren't completely out of values yet.  Any failure here is
                 * really a soft failure. */
                if ((config_entry->next_range_lower == 0) &&
                    (config_entry->remaining <= config_entry->threshold)) {
                    slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                                  "_dna_pre_op_add - Passed threshold of %" PRIu64 " remaining values "
                                  "for range %s. (%" PRIu64 " values remain)\n",
                                  config_entry->threshold, config_entry->dn,
                                  config_entry->remaining);
                    dna_fix_maxval(config_entry, 0);
                }

                slapi_unlock_mutex(config_entry->lock);
            } else if (types_to_generate) {
                slapi_ch_free((void **)&types_to_generate);
            }
        next:
            ret = DNA_SUCCESS;
            list = PR_NEXT_LINK(list);
        }
    }

    dna_unlock();

    slapi_ch_array_free(generated_types);
bail:
    return ret;
}

/* This function is called at BEPREOP timing to add uid/gidNumber
 * if modtype is missing */
static int
_dna_pre_op_modify(Slapi_PBlock *pb, Slapi_Entry *e, Slapi_Mods *smods, char **errstr)
{
    int ret = DNA_SUCCESS;
    PRCList *list = NULL;
    struct configEntry *config_entry = NULL;
    char *dn = NULL;
    char *value = NULL;
    Slapi_Mod *next_mod = NULL;
    Slapi_Mod *smod = NULL;
    Slapi_Attr *attr = NULL;
    char *type = NULL;
    int e_numvals = 0;
    int numvals = 0;
    struct berval *bv = NULL;
    char **types_to_generate = NULL;
    char **generated_types = NULL;
    PRUint64 setval = 0;
    int len = 0;
    int i;

    if (0 == (dn = dna_get_dn(pb))) {
        goto bail;
    }
    /*
     *  Find the config that matches this entry, Set the types that need to be
     *  generated to DNA_NEEDS_UPDATE.  The be_txn_preop will set the values if
     *  the operation hasn't been rejected by that point.
     *
     *  We also check if we need to get the next range of values, and grab them.
     *  We do this here so we don't have to do it in the be_txn_preop.
     */
    dna_read_lock();

    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        list = PR_LIST_HEAD(dna_global_config);

        while (list != dna_global_config && LDAP_SUCCESS == ret) {
            config_entry = (struct configEntry *)list;

            /* Did we already service all of these configured types? */
            if (dna_list_contains_types(generated_types, config_entry->types)) {
                goto next;
            }

            /* is the entry in scope? */
            if (config_entry->scope &&
                !slapi_dn_issuffix(dn, config_entry->scope)) {
                goto next;
            }

            /* is this entry in an excluded scope? */
            for (i = 0; config_entry->excludescope && config_entry->excludescope[i]; i++) {
                if (slapi_dn_issuffix(dn, slapi_sdn_get_dn(config_entry->excludescope[i]))) {
                    goto next;
                }
            }

            /* does the entry match the filter? */
            if (config_entry->slapi_filter) {
                ret = slapi_vattr_filter_test(pb, e,
                                              config_entry->slapi_filter, 0);
                if (LDAP_SUCCESS != ret) {
                    goto next;
                }
            }

            /* check mods for magic value */
            next_mod = slapi_mod_new();
            smod = slapi_mods_get_first_smod(smods, next_mod);
            while (smod) {
                type = (char *)slapi_mod_get_type(smod);

                /* See if the type matches any configured type. */
                if (dna_list_contains_type(config_entry->types, type)) {
                    /* If all values are being deleted, we need to
                     * generate a new value.  We don't do this for
                     * multi-type ranges since they require the magic
                     * value to be specified to trigger generation. */
                    if (SLAPI_IS_MOD_DELETE(slapi_mod_get_operation(smod)) &&
                        !dna_is_multitype_range(config_entry)) {
                        numvals = slapi_mod_get_num_values(smod);

                        if (numvals == 0) {
                            slapi_ch_array_add(&types_to_generate,
                                               slapi_ch_strdup(type));
                        } else {
                            e_numvals = 0;
                            slapi_entry_attr_find(e, type, &attr);
                            if (attr) {
                                slapi_attr_get_numvalues(attr, &e_numvals);
                                if (numvals >= e_numvals) {
                                    slapi_ch_array_add(&types_to_generate,
                                                       slapi_ch_strdup(type));
                                }
                            }
                        }
                    } else {
                        /* This is either adding or replacing a value */
                        bv = slapi_mod_get_first_value(smod);

                        /* If this type is already in the to be generated
                         * list, a previous mod in this same modify operation
                         * either removed all values or set the magic value.
                         * It's possible that this mod is adding a valid value,
                         * which means we would not want to generate a new value.
                         * It is safe to remove this type from the to be
                         * generated list since it will be re-added here if
                         * necessary. */
                        if (dna_list_contains_type(types_to_generate, type)) {
                            dna_list_remove_type(types_to_generate, type);
                        }

                        /* If we have a value, see if it's the magic value. */
                        if (bv) {
                            if (config_entry->generate == NULL) {
                                /* we don't have a magic number set, so apply the update */
                                slapi_ch_array_add(&types_to_generate, slapi_ch_strdup(type));
                            } else {
                                len = strlen(config_entry->generate);
                                if (len == bv->bv_len) {
                                    if (!slapi_UTF8NCASECMP(bv->bv_val, config_entry->generate, len)) {
                                        slapi_ch_array_add(&types_to_generate, slapi_ch_strdup(type));
                                    }
                                }
                            }
                        } else if (!dna_is_multitype_range(config_entry)) {
                            /* This is a replace with no new values,
                             * so we need to generate a new value if this
                             * is not a multi-type range. */
                            slapi_ch_array_add(&types_to_generate, slapi_ch_strdup(type));
                        }
                    }
                }
                slapi_mod_done(next_mod);
                smod = slapi_mods_get_next_smod(smods, next_mod);
            }
            slapi_mod_free(&next_mod);

            /* We need to perform one last check for modify operations.  If an
             * entry within the scope has not triggered generation yet, we need
             * to see if a value exists for the managed type in the resulting
             * entry.  This will catch a modify operation that brings an entry
             * into scope for a managed range, but doesn't supply a value for
             * the managed type.  We don't do this for multi-type ranges. */
            if ((!types_to_generate ||
                 (types_to_generate && !types_to_generate[0])) &&
                !dna_is_multitype_range(config_entry)) {
                if (slapi_entry_attr_find(e, config_entry->types[0], &attr) != 0) {
                    slapi_ch_array_add(&types_to_generate,
                                       slapi_ch_strdup(config_entry->types[0]));
                }
            }

            if (types_to_generate && types_to_generate[0]) {
                /* mod - add to mods */
                for (i = 0; types_to_generate && types_to_generate[i]; i++) {
                    slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                                          types_to_generate[i],
                                          /* no need to dup */
                                          DNA_NEEDS_UPDATE);
                }
                /* Update the internalModifersname for this mod op */
                modify_update_last_modified_attr(pb, smods);

                /* Make sure we don't generate for this
                 * type again by keeping a list of types
                 * we have generated for already.
                 */
                if (generated_types == NULL) {
                    /* If we don't have a list of generated types yet,
                     * we can just use the types_to_generate list so
                     * we don't have to allocate anything. */
                    generated_types = types_to_generate;
                    types_to_generate = NULL;
                } else {
                    /* Just reuse the elements out of types_to_generate for the
                     * generated types list to avoid allocating them again. */
                    for (i = 0; types_to_generate && types_to_generate[i]; ++i) {
                        slapi_ch_array_add(&generated_types, types_to_generate[i]);
                        types_to_generate[i] = NULL;
                    }
                }

                /* free up */
                slapi_ch_free_string(&value);
                slapi_ch_array_free(types_to_generate);
                types_to_generate = NULL;

                /*
                 *  Now grab the next value and see if we need to get the next range
                 */
                slapi_lock_mutex(config_entry->lock);

                ret = dna_first_free_value(config_entry, &setval);
                if (LDAP_SUCCESS != ret) {
                    /* check if we overflowed the configured range */
                    if (setval > config_entry->maxval) {
                        /* try for a new range or fail */
                        ret = dna_fix_maxval(config_entry, 0);
                        if (LDAP_SUCCESS != ret) {
                            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                                          "_dna_pre_op_modify - No more values available!!\n");
                            /* Set an error string to be returned to the client. */
                            *errstr = slapi_ch_smprintf("Allocation of a new value for range"
                                                        " %s failed! Unable to proceed.",
                                                        config_entry->dn);
                            slapi_unlock_mutex(config_entry->lock);
                            break;
                        }

                        /* Make sure dna_first_free_value() doesn't error out */
                        ret = dna_first_free_value(config_entry, &setval);
                        if (LDAP_SUCCESS != ret) {
                            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                                          "_dna_pre_op_modify - Failed to allocate a new ID\n");
                            /* Set an error string to be returned to the client. */
                            *errstr = slapi_ch_smprintf("Allocation of a new value for range"
                                                        " %s failed! Unable to proceed.",
                                                        config_entry->dn);
                            slapi_unlock_mutex(config_entry->lock);
                            break;
                        }
                    } else {
                        /* dna_first_free_value() failed for some unknown reason */
                        slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                                      "_dna_pre_op_modify - Failed to allocate a new ID!!\n");
                        /* Set an error string to be returned to the client. */
                        *errstr = slapi_ch_smprintf("Allocation of a new value for range"
                                                    " %s failed! Unable to proceed.",
                                                    config_entry->dn);
                        slapi_unlock_mutex(config_entry->lock);
                        break;
                    }
                }

                /* Check if we passed the threshold and try to fix maxval if so.
                 * We don't need to do this if we already have a next range on
                 * deck.  We don't check the result of dna_fix_maxval() since
                 * we aren't completely out of values yet.  Any failure here is
                 * really a soft failure. */
                if ((config_entry->next_range_lower == 0) &&
                    (config_entry->remaining <= config_entry->threshold)) {
                    slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                                  "_dna_pre_op_modify - Passed threshold of %" PRIu64 " remaining values "
                                  "for range %s. (%" PRIu64 " values remain)\n",
                                  config_entry->threshold, config_entry->dn,
                                  config_entry->remaining);
                    dna_fix_maxval(config_entry, 0);
                }

                slapi_unlock_mutex(config_entry->lock);
            } else if (types_to_generate) {
                slapi_ch_free((void **)&types_to_generate);
            }
        next:
            ret = 0;
            list = PR_NEXT_LINK(list);
        }
    }

    dna_unlock();

    slapi_ch_array_free(generated_types);
bail:
    return ret;
}
/* for mods and adds:
   where dn's are supplied, the closest in scope
   is used as long as the type filter matches
   and the type has not been generated yet.
*/

static int
dna_pre_op(Slapi_PBlock *pb, int modtype)
{
    struct slapi_entry *e = NULL;
    Slapi_Entry *test_e = NULL;
    Slapi_Entry *resulting_e = NULL;
    char *errstr = NULL;
    char *dn = NULL;
    Slapi_Mods *smods = NULL;
    LDAPMod **mods;
    int ret = 0;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_pre_op\n");

    if (0 == (dn = dna_get_dn(pb))) {
        goto bail;
    }

    if (dna_isrepl(pb)) {
        /* if repl, the dna values should be already in the entry. */
        goto bail;
    }

    if (LDAP_CHANGETYPE_ADD == modtype) {
        slapi_pblock_get(pb, SLAPI_ADD_ENTRY, &e);
        if (NULL == e) {
            slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                          "dna_pre_op - No add entry set for add\n");
            goto bail;
        }
    } else {
        slapi_pblock_get(pb, SLAPI_MODIFY_EXISTING_ENTRY, &e);
        if (NULL == e) {
            slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                          "dna_pre_op - No pre op entry set for modify\n");
            goto bail;
        }
        /* grab the mods - we'll put them back later with our modifications appended */
        slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);

        /* We need the resulting entry after the mods are applied to
         * see if the entry is within the scope. */
        resulting_e = slapi_entry_dup(e);
        if (mods &&
            (slapi_entry_apply_mods(resulting_e, mods) != LDAP_SUCCESS)) {
            /* The mods don't apply cleanly, so we just let this op go
             * to let the main server handle it. */
            goto bail;
        }
        smods = slapi_mods_new();
        slapi_mods_init_passin(smods, mods);
    }

    /* For a MOD, we need to check the resulting entry */
    if (LDAP_CHANGETYPE_ADD == modtype) {
        test_e = e;
    } else {
        test_e = resulting_e;
    }

    if (dna_dn_is_config(dn)) {
        /* Validate config changes, but don't apply them.
         * This allows us to reject invalid config changes
         * here at the pre-op stage.  Applying the config
         * needs to be done at the post-op stage. */

        if (dna_parse_config_entry(pb, test_e, 0) != DNA_SUCCESS) {
            /* Refuse the operation if config parsing failed. */
            ret = LDAP_UNWILLING_TO_PERFORM;
            if (LDAP_CHANGETYPE_ADD == modtype) {
                errstr = slapi_ch_smprintf("Not a valid DNA configuration entry.");
            } else {
                errstr = slapi_ch_smprintf("Changes result in an invalid "
                                           "DNA configuration.");
            }
        }
    } else {
        if (LDAP_CHANGETYPE_ADD == modtype) {
            ret = _dna_pre_op_add(pb, test_e, &errstr);
        } else {
            if ((ret = _dna_pre_op_modify(pb, test_e, smods, &errstr))) {
                slapi_mods_free(&smods);
            }
        }
        if (ret) {
            goto bail;
        }
    }

    /* We're done. */
    if (LDAP_CHANGETYPE_MODIFY == modtype) {
        /* Put the updated mods back into place. */
        mods = slapi_mods_get_ldapmods_passout(smods);
        slapi_pblock_set(pb, SLAPI_MODIFY_MODS, mods);
        slapi_mods_free(&smods);
    }
bail:
    if (resulting_e)
        slapi_entry_free(resulting_e);
    slapi_mods_free(&smods);

    if (ret) {
        slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                      "dna_pre_op - Operation failure [%d]\n", ret);
        slapi_send_ldap_result(pb, ret, NULL, errstr, 0, NULL);
        slapi_ch_free((void **)&errstr);
        slapi_pblock_set(pb, SLAPI_RESULT_CODE, &ret);
        ret = DNA_FAILURE;
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_pre_op\n");

    return ret;
}

static int
dna_add_pre_op(Slapi_PBlock *pb)
{
    return dna_pre_op(pb, LDAP_CHANGETYPE_ADD);
}

static int
dna_mod_pre_op(Slapi_PBlock *pb)
{
    return dna_pre_op(pb, LDAP_CHANGETYPE_MODIFY);
}

static int
dna_be_txn_add_pre_op(Slapi_PBlock *pb)
{
    return dna_be_txn_pre_op(pb, LDAP_CHANGETYPE_ADD);
}

static int
dna_be_txn_mod_pre_op(Slapi_PBlock *pb)
{
    return dna_be_txn_pre_op(pb, LDAP_CHANGETYPE_MODIFY);
}

/*
 *  dna_be_txn_pre_op()
 *
 *  In the preop if we found that we need to update a DNA attribute,
 *  We set the value to "-2" or DNA_NEEDS_UPDATE, because we don't want
 *  to do the value allocation in the preop as the operation could fail -
 *  resulting in lost values from the range.  So we need to to ensure
 *  that the value will not be lost by performing the value allocation
 *  in the backend txn preop.
 *
 *  Although the modifications have already been applied in backend,
 *  we still need to add the modification of the real value to the
 *  existing Slapi_Mods, so that the value gets indexed correctly.
 *
 *  Also, since the modifications have already been applied to the entry
 *  in the backend, we need to manually update the entry with the new value.
 */
static int
dna_be_txn_pre_op(Slapi_PBlock *pb, int modtype)
{
    struct configEntry *config_entry = NULL;
    struct slapi_entry *e = NULL;
    Slapi_Mods *smods = NULL;
    Slapi_Mod *smod = NULL;
    Slapi_Mod *next_mod = NULL;
    Slapi_Attr *attr = NULL;
    LDAPMod **mods = NULL;
    struct berval *bv = NULL;
    PRCList *list = NULL;
    char *value = NULL;
    char **types_to_generate = NULL;
    char **generated_types = NULL;
    char *new_value = NULL;
    char *errstr = NULL;
    char *dn = NULL;
    char *type = NULL;
    int numvals, e_numvals = 0;
    int i, len, ret = DNA_SUCCESS;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_be_txn_pre_op\n");

    if (!slapi_plugin_running(pb)) {
        slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM, "dna_be_txn_pre_op - Bailing, plugin not running\n");
        goto bail;
    }

    if (0 == (dn = dna_get_dn(pb))) {
        slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM, "dna_be_txn_pre_op - Bailing, is dna dn\n");
        goto bail;
    }

    if (dna_dn_is_config(dn)) {
        slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM, "dna_be_txn_pre_op - Bailing is dna config dn\n");
        goto bail;
    }

    if (dna_isrepl(pb)) {
        slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM, "dna_be_txn_pre_op - Bailing replicated operation\n");
        /* if repl, the dna values should be already in the entry. */
        goto bail;
    }

    if (LDAP_CHANGETYPE_ADD == modtype) {
        slapi_pblock_get(pb, SLAPI_ADD_ENTRY, &e);
    } else {
        slapi_pblock_get(pb, SLAPI_MODIFY_EXISTING_ENTRY, &e);
    }

    if (e == NULL) {
        slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM, "dna_be_txn_pre_op - Bailing entry is NULL\n");
        goto bail;
    } else if (LDAP_CHANGETYPE_MODIFY == modtype) {
        slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
        smods = slapi_mods_new();
        slapi_mods_init_passin(smods, mods);
    }

    dna_read_lock();

    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        list = PR_LIST_HEAD(dna_global_config);
        slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM, "dna_be_txn_pre_op - Using global config...\n");

        while (list != dna_global_config && LDAP_SUCCESS == ret) {
            config_entry = (struct configEntry *)list;

            /* Did we already service all of these configured types? */
            if (dna_list_contains_types(generated_types, config_entry->types)) {
                slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM, "dna_be_txn_pre_op - All types already serviced\n");
                goto next;
            }

            /* is the entry in scope? */
            if (config_entry->scope) {
                if (!slapi_dn_issuffix(dn, config_entry->scope)) {
                    slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM, "dna_be_txn_pre_op - Entry not in scope of dnaScope!\n");
                    goto next;
                }
            }

            /* is this entry in an excluded scope? */
            for (i = 0; config_entry->excludescope && config_entry->excludescope[i]; i++) {
                if (slapi_dn_issuffix(dn, slapi_sdn_get_dn(config_entry->excludescope[i]))) {
                    slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM, "dna_be_txn_pre_op - Entry in excluded scope, next\n");
                    goto next;
                }
            }

            /* does the entry match the filter? */
            if (config_entry->slapi_filter) {
                if (LDAP_SUCCESS != slapi_vattr_filter_test(pb, e, config_entry->slapi_filter, 0)) {
                    slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM, "dna_be_txn_pre_op - Entry does not match filter\n");
                    goto next;
                }
            }

            if (LDAP_CHANGETYPE_ADD == modtype) {
                if (dna_is_multitype_range(config_entry)) {
                    /* For a multi-type range, we only generate a value
                     * for types where the magic value is set.  We do not
                     * generate a value for missing types. */
                    for (i = 0; config_entry->types && config_entry->types[i]; i++) {
                        value = slapi_entry_attr_get_charptr(e, config_entry->types[i]);

                        if (value && !slapi_UTF8CASECMP(value, DNA_NEEDS_UPDATE)) {
                            slapi_ch_array_add(&types_to_generate,
                                               slapi_ch_strdup(config_entry->types[i]));
                            /* Need to remove DNA_NEEDS_UPDATE */
                            slapi_entry_attr_delete(e, config_entry->types[i]);
                        }
                        slapi_ch_free_string(&value);
                    }
                } else {
                    /* For a single type range, we generate the value if
                     * the magic value is set or if the type is missing. */
                    value = slapi_entry_attr_get_charptr(e, config_entry->types[0]);

                    if (0 == value || (value && !slapi_UTF8CASECMP(value, DNA_NEEDS_UPDATE))) {
                        slapi_ch_array_add(&types_to_generate,
                                           slapi_ch_strdup(config_entry->types[0]));
                        /* Need to remove DNA_NEEDS_UPDATE */
                        slapi_entry_attr_delete(e, config_entry->types[0]);
                    }
                    slapi_ch_free_string(&value);
                }
            } else {
                /* check mods for DNA_NEEDS_UPDATE*/
                next_mod = slapi_mod_new();
                smod = slapi_mods_get_first_smod(smods, next_mod);
                while (smod) {
                    type = (char *)slapi_mod_get_type(smod);

                    /* See if the type matches any configured type. */
                    if (dna_list_contains_type(config_entry->types, type)) {
                        /* If all values are being deleted, we need to
                         * generate a new value. */
                        if (SLAPI_IS_MOD_DELETE(slapi_mod_get_operation(smod)) &&
                            !dna_is_multitype_range(config_entry)) {
                            numvals = slapi_mod_get_num_values(smod);

                            if (numvals == 0) {
                                slapi_ch_array_add(&types_to_generate, slapi_ch_strdup(type));
                            } else {
                                slapi_entry_attr_find(e, type, &attr);
                                if (attr) {
                                    slapi_attr_get_numvalues(attr, &e_numvals);
                                    if (numvals >= e_numvals) {
                                        slapi_ch_array_add(&types_to_generate,
                                                           slapi_ch_strdup(type));
                                    }
                                }
                            }
                        } else {
                            /* This is either adding or replacing a value */
                            bv = slapi_mod_get_first_value(smod);

                            if (dna_list_contains_type(types_to_generate, type)) {
                                dna_list_remove_type(types_to_generate, type);
                            }

                            /* If we have a value, see if it's the magic value. */
                            if (bv) {
                                if (!slapi_UTF8CASECMP(bv->bv_val,
                                                       DNA_NEEDS_UPDATE)) {
                                    slapi_ch_array_add(&types_to_generate, slapi_ch_strdup(type));
                                }
                            } else if (!dna_is_multitype_range(config_entry)) {
                                /* This is a replace with no new values, so we need
                                 * to generate a new value if this is not a multi-type range. */
                                slapi_ch_array_add(&types_to_generate, slapi_ch_strdup(type));
                            }
                        }
                    }
                    slapi_mod_done(next_mod);
                    smod = slapi_mods_get_next_smod(smods, next_mod);
                }
                slapi_mod_free(&next_mod);
            }
            /* We need to perform one last check for modify operations.  If an
             * entry within the scope has not triggered generation yet, we need
             * to see if a value exists for the managed type in the resulting
             * entry.  This will catch a modify operation that brings an entry
             * into scope for a managed range, but doesn't supply a value for
             * the managed type.  We don't do this for multi-type ranges. */
            if ((LDAP_CHANGETYPE_MODIFY == modtype) && (!types_to_generate ||
                                                        (types_to_generate && !types_to_generate[0])) &&
                !dna_is_multitype_range(config_entry)) {
                if (slapi_entry_attr_find(e, config_entry->types[0], &attr) != 0) {
                    slapi_ch_array_add(&types_to_generate, slapi_ch_strdup(config_entry->types[0]));
                }
            }

            if (types_to_generate && types_to_generate[0]) {
                /* create the value to add */
                ret = dna_get_next_value(config_entry, &value);
                if (DNA_SUCCESS != ret) {
                    errstr = slapi_ch_smprintf("Allocation of a new value for range"
                                               " %s failed! Unable to proceed.",
                                               config_entry->dn);
                    slapi_ch_array_free(types_to_generate);
                    break;
                }

                len = strlen(value) + 1;
                if (config_entry->prefix) {
                    len += strlen(config_entry->prefix);
                }

                new_value = slapi_ch_malloc(len);

                if (config_entry->prefix) {
                    strcpy(new_value, config_entry->prefix);
                    strcat(new_value, value);
                } else
                    strcpy(new_value, value);
                /* do the mod */
                if (LDAP_CHANGETYPE_ADD == modtype) {
                    /* add - add to entry */
                    for (i = 0; types_to_generate && types_to_generate[i]; i++) {
                        slapi_entry_attr_set_charptr(e, types_to_generate[i], new_value);
                    }
                } else {
                    for (i = 0; types_to_generate && types_to_generate[i]; i++) {
                        slapi_mods_add_string(smods, LDAP_MOD_REPLACE, types_to_generate[i], new_value);

                        /* we need to directly update the entry in be_txn_preop */
                        slapi_entry_attr_set_charptr(e, types_to_generate[i], new_value);
                    }
                }
                /*
                 * Make sure we don't generate for this
                 * type again by keeping a list of types
                 * we have generated for already.
                 */
                if (LDAP_SUCCESS == ret) {
                    if (generated_types == NULL) {
                        /* If we don't have a list of generated types yet,
                         * we can just use the types_to_generate list so
                         * we don't have to allocate anything. */
                        generated_types = types_to_generate;
                        types_to_generate = NULL;
                    } else {
                        /* Just reuse the elements out of types_to_generate for the
                         * generated types list to avoid allocating them again. */
                        for (i = 0; types_to_generate && types_to_generate[i]; ++i) {
                            slapi_ch_array_add(&generated_types, types_to_generate[i]);
                            types_to_generate[i] = NULL;
                        }
                    }
                }

                /* free up */
                slapi_ch_free_string(&value);
                slapi_ch_free_string(&new_value);
                slapi_ch_array_free(types_to_generate);
                types_to_generate = NULL;
            } else if (types_to_generate) {
                slapi_ch_free((void **)&types_to_generate);
            }
        next:
            list = PR_NEXT_LINK(list);
        }
    }
    dna_unlock();
bail:

    if (LDAP_CHANGETYPE_MODIFY == modtype) {
        /* Put the updated mods back into place. */
        if (smods) { /* smods == NULL if we bailed before initializing it */
            mods = slapi_mods_get_ldapmods_passout(smods);
            slapi_pblock_set(pb, SLAPI_MODIFY_MODS, mods);
            slapi_mods_free(&smods);
        }
    }

    slapi_ch_array_free(generated_types);

    if (ret) {
        slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                      "dna_be_txn_pre_op - Operation failure [%d]\n", ret);
        slapi_send_ldap_result(pb, ret, NULL, errstr, 0, NULL);
        slapi_ch_free((void **)&errstr);
        slapi_pblock_set(pb, SLAPI_RESULT_CODE, &ret);
        ret = DNA_FAILURE;
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_be_txn_pre_op\n");

    return ret;
}

static int
dna_config_check_post_op(Slapi_PBlock *pb)
{
    char *dn;

    if (!slapi_plugin_running(pb)) {
        return DNA_SUCCESS;
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_config_check_post_op\n");


    if (!slapi_op_internal(pb)) { /* If internal, no need to check. */
        if ((dn = dna_get_dn(pb))) {
            if (dna_dn_is_config(dn)) {
                dna_load_plugin_config(pb, 0);
            }
            if (dna_dn_is_shared_config(pb, dn)) {
                dna_load_shared_servers();
            }
        }
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_config_check_post_op\n");

    return DNA_SUCCESS;
}


/****************************************************
 * Pre Extended Operation, Backend selection
 ***************************************************/
static int
dna_extend_exop_backend(Slapi_PBlock *pb, Slapi_Backend **target)
{
    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_parse_exop_backend\n");
    Slapi_DN *shared_sdn = NULL;
    char *shared_dn = NULL;
    int res = -1;
    /* Parse the oid and what exop wants us to do */
    res = dna_parse_exop_ber(pb, &shared_dn);
    if (res != LDAP_SUCCESS) {
        return res;
    }
    if (shared_dn) {
        shared_sdn = slapi_sdn_new_dn_byref(shared_dn);
        *target = slapi_be_select(shared_sdn);
        slapi_sdn_free(&shared_sdn);
    }
    res = LDAP_SUCCESS;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_parse_exop_backend %d\n", res);
    return res;
}


/****************************************************
 * Range Extension Extended Operation
 ***************************************************/
static int
dna_extend_exop(Slapi_PBlock *pb)
{
    int ret = SLAPI_PLUGIN_EXTENDED_NOT_HANDLED;
    char *shared_dn = NULL;
    char *bind_dn = NULL;
    PRUint64 lower = 0;
    PRUint64 upper = 0;

    if (!slapi_plugin_running(pb)) {
        return ret;
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_extend_exop\n");

    if (dna_parse_exop_ber(pb, &shared_dn) != LDAP_SUCCESS) {
        return ret;
    }

    slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                  "dna_extend_exop - Received range extension "
                  "request for range [%s]\n",
                  shared_dn);

    /* Only allow range requests from the replication bind DN user */
    slapi_pblock_get(pb, SLAPI_CONN_DN, &bind_dn);
    if (!dna_is_replica_bind_dn(shared_dn, bind_dn)) {
        ret = LDAP_INSUFFICIENT_ACCESS;
        goto free_and_return;
    }

    /* See if we have the req. range configured.
     * If so, we need to see if we have range to provide. */
    ret = dna_release_range(shared_dn, &lower, &upper);

    if (ret == LDAP_SUCCESS) {
        /* We have range to give away, so construct
         * and send the response. */
        BerElement *respber = NULL;
        struct berval *respdata = NULL;
        struct berval range_low = {0, NULL};
        struct berval range_high = {0, NULL};
        char lowstr[22];
        char highstr[22];

        /* Create the exop response */
        snprintf(lowstr, sizeof(lowstr), "%" PRIu64, lower);
        snprintf(highstr, sizeof(highstr), "%" PRIu64, upper);
        range_low.bv_val = lowstr;
        range_low.bv_len = strlen(range_low.bv_val);
        range_high.bv_val = highstr;
        range_high.bv_len = strlen(range_high.bv_val);

        if ((respber = ber_alloc()) == NULL) {
            ret = LDAP_NO_MEMORY;
            goto free_and_return;
        }

        if (LBER_ERROR == (ber_printf(respber, "{oo}",
                                      range_low.bv_val, range_low.bv_len,
                                      range_high.bv_val, range_high.bv_len))) {
            slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                          "dna_extend_exop - Unable to encode exop response.\n");
            ber_free(respber, 1);
            ret = LDAP_ENCODING_ERROR;
            goto free_and_return;
        }

        ber_flatten(respber, &respdata);
        ber_free(respber, 1);

        slapi_pblock_set(pb, SLAPI_EXT_OP_RET_OID, DNA_EXTEND_EXOP_RESPONSE_OID);
        slapi_pblock_set(pb, SLAPI_EXT_OP_RET_VALUE, respdata);

        /* send the response ourselves */
        slapi_send_ldap_result(pb, ret, NULL, NULL, 0, NULL);
        ret = SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
        ber_bvfree(respdata);

        slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                      "dna_extend_exop - Released range %" PRIu64 "-%" PRIu64 ".\n",
                      lower, upper);
    }

free_and_return:
    slapi_ch_free_string(&shared_dn);
    slapi_ch_free_string(&bind_dn);

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_extend_exop\n");

    return ret;
}

/*
 * dna_release_range()
 *
 * Checks if we have any values that we can release
 * for the range specified by range_dn.
 */
static int
dna_release_range(char *range_dn, PRUint64 *lower, PRUint64 *upper)
{
    int ret = 0;
    int match = 0;
    PRCList *list = NULL;
    Slapi_DN *cfg_base_sdn = NULL;
    Slapi_DN *range_sdn = NULL;
    struct configEntry *config_entry = NULL;
    int set_extend_flag = 0;

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "--> dna_release_range\n");

    if (range_dn) {
        range_sdn = slapi_sdn_new_dn_byref(range_dn);

        dna_read_lock();

        /* Go through the config entries to see if we
         * have a shared range configured that matches
         * the range from the exop request. */
        if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
            list = PR_LIST_HEAD(dna_global_config);
            while ((list != dna_global_config) && match != 1) {
                config_entry = (struct configEntry *)list;
                cfg_base_sdn = slapi_sdn_new_normdn_byref(config_entry->shared_cfg_base);

                if (slapi_sdn_compare(cfg_base_sdn, range_sdn) == 0) {
                    /* We found a match.  Set match flag to
                     * break out of the loop. */
                    match = 1;
                } else {
                    config_entry = NULL;
                    list = PR_NEXT_LINK(list);
                }

                slapi_sdn_free(&cfg_base_sdn);
            }
        }

        /* config_entry will point to our match if we found one */
        if (config_entry) {
            int release = 0;
            Slapi_PBlock *pb = NULL;
            LDAPMod mod_replace;
            LDAPMod *mods[2];
            char *replace_val[2];
            /* 16 for max 64-bit unsigned plus the trailing '\0' */
            char max_value[22];

            /* Need to bail if we're performing a range request
             * for this range.  This is to prevent the case where two
             * servers are asking each other for more range for the
             * same managed range.  This would result in a network
             * deadlock until the idletimeout kills one of the
             * connections. */
            slapi_lock_mutex(config_entry->extend_lock);
            if (config_entry->extend_in_progress) {
                /* We're already processing a range extention, so bail. */
                slapi_log_err(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                              "dna_release_range - Already processing a "
                              "range extension request.  Skipping request.\n");
                slapi_unlock_mutex(config_entry->extend_lock);
                ret = LDAP_UNWILLING_TO_PERFORM;
                goto bail;
            } else {
                /* Set a flag indicating that we're attempting to extend this range */
                config_entry->extend_in_progress = 1;
                set_extend_flag = 1;
                slapi_unlock_mutex(config_entry->extend_lock);
            }

            /* Obtain the lock for this range */
            slapi_lock_mutex(config_entry->lock);

            /* Refuse if we're at or below our threshold */
            if (config_entry->remaining <= config_entry->threshold) {
                ret = LDAP_UNWILLING_TO_PERFORM;
                goto bail;
            }

            /* If we have a next range, we need to give up values from
             * it instead of from the active range */
            if (config_entry->next_range_lower != 0) {
                /* Release up to half of our values from the next range. */
                if (config_entry->threshold == 0) {
                    ret = LDAP_UNWILLING_TO_PERFORM;
                    goto bail;
                }

                release = (((config_entry->next_range_upper - config_entry->next_range_lower + 1) /
                            2) /
                           config_entry->threshold) *
                          config_entry->threshold;

                if (release == 0) {
                    ret = LDAP_UNWILLING_TO_PERFORM;
                    goto bail;
                }

                *upper = config_entry->next_range_upper;
                *lower = *upper - release + 1;

                /* Try to set the new next range in the config */
                ret = dna_update_next_range(config_entry, config_entry->next_range_lower,
                                            *lower - 1);
            } else {
                /* We release up to half of our remaining values,
                 * but we'll only release a range that is a multiple
                 * of our threshold. */
                release = ((config_entry->remaining / 2) /
                           config_entry->threshold) *
                          config_entry->threshold;

                if (release == 0) {
                    ret = LDAP_UNWILLING_TO_PERFORM;
                    goto bail;
                }

                /* We give away values from the upper end of our range. */
                *upper = config_entry->maxval;
                *lower = *upper - release + 1;

                /* try to set the new maxval in the config entry */
                snprintf(max_value, sizeof(max_value), "%" PRIu64, (*lower - 1));

                /* set up our replace modify operation */
                replace_val[0] = max_value;
                replace_val[1] = 0;
                mod_replace.mod_op = LDAP_MOD_REPLACE;
                mod_replace.mod_type = DNA_MAXVAL;
                mod_replace.mod_values = replace_val;
                mods[0] = &mod_replace;
                mods[1] = 0;

                pb = slapi_pblock_new();
                if (NULL == pb) {
                    ret = LDAP_OPERATIONS_ERROR;
                    goto bail;
                }

                slapi_modify_internal_set_pb(pb, config_entry->dn,
                                             mods, 0, 0, getPluginID(), 0);

                slapi_modify_internal_pb(pb);

                slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

                slapi_pblock_destroy(pb);
                pb = NULL;

                if (ret == LDAP_SUCCESS) {
                    /* Adjust maxval in our cached config and shared config */
                    config_entry->maxval = *lower - 1;
                    /* This is within the dna_lock, so okay */
                    dna_notice_allocation(config_entry, config_entry->nextval, 0);
                }
            }

            if (ret != LDAP_SUCCESS) {
                /* Updating the config failed, so reset. We don't
                     * want to give the caller any range */
                *lower = 0;
                *upper = 0;
                slapi_log_err(SLAPI_LOG_ERR, DNA_PLUGIN_SUBSYSTEM,
                              "dna_release_range - Error updating "
                              "configuration entry [err=%d]\n",
                              ret);
            }
        }

    bail:
        if (set_extend_flag) {
            slapi_lock_mutex(config_entry->extend_lock);
            config_entry->extend_in_progress = 0;
            slapi_unlock_mutex(config_entry->extend_lock);
        }

        if (config_entry) {
            slapi_unlock_mutex(config_entry->lock);
        }
        slapi_sdn_free(&range_sdn);

        dna_unlock();
    }

    slapi_log_err(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                  "<-- dna_release_range\n");

    return ret;
}

/****************************************************
    End of
    Functions that actually do things other
    than config and startup
****************************************************/

/**
 * debug functions to print config
 */
void
dna_dump_config(void)
{
    PRCList *list;

    dna_read_lock();

    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        list = PR_LIST_HEAD(dna_global_config);
        while (list != dna_global_config) {
            dna_dump_config_entry((struct configEntry *)list);
            list = PR_NEXT_LINK(list);
        }
    }

    dna_unlock();
}

/*
 * dna_isrepl()
 *
 * Returns 1 if the operation associated with pb
 * is a replicated op.  Returns 0 otherwise.
 */
static int
dna_isrepl(Slapi_PBlock *pb)
{
    int is_repl = 0;

    slapi_pblock_get(pb, SLAPI_IS_REPLICATED_OPERATION, &is_repl);

    return is_repl;
}


void
dna_dump_config_entry(struct configEntry *entry)
{
    int i = 0;

    for (i = 0; entry->types && entry->types[i]; i++) {
        printf("<---- type -----------> %s\n", entry->types[i]);
    }
    printf("<---- filter ---------> %s\n", entry->filter);
    printf("<---- prefix ---------> %s\n", entry->prefix);
    printf("<---- scope ----------> %s\n", entry->scope);
    for (i = 0; entry->excludescope && entry->excludescope[i]; i++) {
        printf("<---- excluded scope -> %s\n", slapi_sdn_get_dn(entry->excludescope[i]));
    }
    printf("<---- next value -----> %" PRIu64 "\n", entry->nextval);
    printf("<---- max value ------> %" PRIu64 "\n", entry->maxval);
    printf("<---- interval -------> %" PRIu64 "\n", entry->interval);
    printf("<---- generate flag --> %s\n", entry->generate);
    printf("<---- shared cfg base > %s\n", entry->shared_cfg_base);
    printf("<---- shared cfg DN --> %s\n", entry->shared_cfg_dn);
    printf("<---- threshold ------> %" PRIu64 "", entry->threshold);
}

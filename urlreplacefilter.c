#include "httpd.h"
#include "http_config.h"
#include "apr_buckets.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "http_request.h"

#include <ctype.h>

static const char s_szurlReplaceFilterName[]="urlReplaceFilter";
module AP_MODULE_DECLARE_DATA urlReplace_filter_module;

typedef struct
{
    int bEnabled;
    const  char *src_path;
    const  char *desc_path;
} urlReplaceFilterConfig;

static void *urlReplaceFilterCreateServerConfig(apr_pool_t *p,server_rec *s)
{
    urlReplaceFilterConfig *pConfig=apr_pcalloc(p,sizeof *pConfig);
    pConfig->bEnabled=0;
    return pConfig;
}

static void urlReplaceFilterInsertFilter(request_rec *r)
{
    urlReplaceFilterConfig *pConfig=ap_get_module_config(r->server->module_config,
                              &urlReplace_filter_module);

    if (!pConfig->bEnabled)
        return;

    ap_add_output_filter(s_szurlReplaceFilterName,NULL,r,r->connection);
}

static apr_status_t urlReplaceFilterOutFilter(ap_filter_t *f,
                                        apr_bucket_brigade *pbbIn)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    apr_bucket *pbktIn;
    apr_bucket_brigade *pbbOut;

    pbbOut=apr_brigade_create(r->pool, c->bucket_alloc);
    for (pbktIn = APR_BRIGADE_FIRST(pbbIn);
            pbktIn != APR_BRIGADE_SENTINEL(pbbIn);
            pbktIn = APR_BUCKET_NEXT(pbktIn))
    {
        const char *data;
        apr_size_t len;
        char *buf;
        apr_size_t n;
        apr_bucket *pbktOut;

        if (APR_BUCKET_IS_EOS(pbktIn))
        {
            apr_bucket *pbktEOS=apr_bucket_eos_create(c->bucket_alloc);
            APR_BRIGADE_INSERT_TAIL(pbbOut,pbktEOS);
            continue;
        }

        /* read */
        apr_bucket_read(pbktIn,&data,&len,APR_BLOCK_READ);

        /* write */
        buf = apr_bucket_alloc(len, c->bucket_alloc);
        for (n=0 ; n < len ; ++n)
            buf[n] = apr_toupper(data[n]);

        pbktOut = apr_bucket_heap_create(buf, len, apr_bucket_free,
                                         c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(pbbOut,pbktOut);
    }
    apr_brigade_cleanup(pbbIn);
    return ap_pass_brigade(f->next,pbbOut);
}

static const char *urlReplaceFilterEnable(cmd_parms *cmd, void *dummy, int arg)
{
    urlReplaceFilterConfig *pConfig=ap_get_module_config(cmd->server->module_config,
                              &urlReplace_filter_module);
    pConfig->bEnabled=arg;

    return NULL;
}
static const char *set_src_path(cmd_parms *cmd,void *mconfig,const char *arg)
{
  urlReplaceFilterConfig *pConfig=ap_get_module_config(cmd->server->module_config,&urlReplace_filter_module);
  pConfig->src_path = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

static const char *set_desc_path(cmd_parms *cmd,void *mconfig,const char *arg)
{
  urlReplaceFilterConfig *pConfig=ap_get_module_config(cmd->server->module_config,&urlReplace_filter_module);
  pConfig->desc_path = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

static const command_rec urlReplaceFilterCmds[] =
{
    AP_INIT_FLAG("urlReplaceFilter", urlReplaceFilterEnable, NULL, RSRC_CONF,
    "Run a urlReplace filter on this host"),
    AP_INIT_TAKE1("srcpath", set_src_path, NULL, OR_FILEINFO,"src path regex must not be null"),
    AP_INIT_TAKE1("descpath", set_desc_path, NULL, OR_FILEINFO,"desc path must not be null"),
    { NULL }
};

static void urlReplaceFilterRegisterHooks(apr_pool_t *p)
{
    ap_hook_insert_filter(urlReplaceFilterInsertFilter,NULL,NULL,APR_HOOK_MIDDLE);
    ap_register_output_filter(s_szurlReplaceFilterName,urlReplaceFilterOutFilter,NULL,
                              AP_FTYPE_RESOURCE);
}

module AP_MODULE_DECLARE_DATA urlReplace_filter_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    urlReplaceFilterCreateServerConfig,
    NULL,
    urlReplaceFilterCmds,
    urlReplaceFilterRegisterHooks
};


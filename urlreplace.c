#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_want.h"
//该模块的配置信息定义一个结构。
typedef struct
{
  const  char *src_path;
  const  char *desc_path;
}auth_jira_conf;
//声明模块名称
module AP_MODULE_DECLARE_DATA pathreplace_module;
// 测试用的handler实际。输出从配置文件中读入的配置信息。
static int pathreplace_handler(request_rec *r)
{
   r->content_type = "text/html";
   //取conf数据
  auth_jira_conf *conf = ap_get_module_config(r->per_dir_config,
    &pathreplace_module);
  ap_rprintf(r, "src_path:%s\n",conf->src_path);
  ap_rprintf(r, "desc_path:%s",conf->desc_path);
   return OK;
}
static void pathreplace_register_hooks(apr_pool_t *p)
{
     ap_hook_handler(pathreplace_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *set_src_path(cmd_parms *cmd,
                                             void *mconfig,
                                             const char *arg)
{
  auth_jira_conf *conf = (auth_jira_conf *) mconfig;
 
  conf->src_path = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

static const char *set_desc_path(cmd_parms *cmd,
                                          void *mconfig,
                                          const char *arg)
{
  auth_jira_conf *conf = (auth_jira_conf *) mconfig;
 
  conf->desc_path = apr_pstrdup(cmd->pool, arg);
  return NULL;
}

static void *create_authjira_dir_config(apr_pool_t *p, char *d)
{
  auth_jira_conf *conf = (auth_jira_conf *)apr_pcalloc(p, sizeof(*conf));
  if(conf == NULL) return NULL;
  conf->src_path          = d;
  conf->desc_path         = d;
  return conf;
}
//对应的http.conf的命令读到方法。
static const command_rec authn_jira_cmds[] =
{
  AP_INIT_TAKE1("srcpath", set_src_path, NULL, OR_FILEINFO,
  "src path regex must not be null"),
  AP_INIT_TAKE1("descpath", set_desc_path, NULL, OR_FILEINFO,
  "desc path must not be null"),
  { NULL }
};

module AP_MODULE_DECLARE_DATA pathreplace_module = {
          STANDARD20_MODULE_STUFF,
         create_authjira_dir_config,
          NULL,                 
          NULL,                 
          NULL,                 
          authn_jira_cmds,                 
          pathreplace_register_hooks
};

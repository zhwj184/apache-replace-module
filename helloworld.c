#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "ap_config.h"

/* The sample content handler */
static int helloworld_handler(request_rec *r)
{
    if (strcmp(r->handler, "helloworld")) {
        return DECLINED;
    }
    r->content_type = "text/html";      

    if (!r->header_only)
        ap_rputs("The sample page from mod_helloworld.c\n", r);
    return OK;
}

static void helloworld_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(helloworld_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA helloworld_module = {
    STANDARD20_MODULE_STUFF, //用于编译后的模块产生版本信息
    NULL,                  /* 创建目录配置结构*/
    NULL,                  /* 合并目录配置结构 */
    NULL,                  /* 创建主机配置结构 */
    NULL,                  /* 合并主机配置结构 */
    NULL,                  /* 为模块配置相关指令       */
    helloworld_register_hooks  /* 注册模块的钩子函数                      */
};


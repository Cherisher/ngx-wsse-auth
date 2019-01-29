
/*
* CMIOT VIDEO TEAM
* create by Candoit
*/
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_crypt.h>
#include <ngx_http.h>
#include <ngx_sha1.h>

#define NGX_HTTP_AUTH_WSSE_USERNOTFOUND 1000

#define NGX_HTTP_AUTH_WSSE_STATUS_SUCCESS 1
#define NGX_HTTP_AUTH_WSSE_STATUS_FAILURE 0

typedef struct {
    ngx_http_complex_value_t *realm;
} ngx_http_auth_wsse_loc_conf_t;

typedef struct {
    ngx_str_t schema;
    ngx_str_t username;
    ngx_str_t pw_digest;
    ngx_str_t nonce;
    ngx_str_t created;
    ngx_int_t stale; //过期的
} ngx_http_auth_wsse_fields_t;

static ngx_inline void ngx_http_auth_wsse_evasion_tracking(ngx_http_request_t *r, ngx_http_auth_wsse_loc_conf_t *alcf, ngx_int_t status);

static ngx_int_t ngx_http_auth_wsse_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_auth_wsse_set_realm(ngx_http_request_t *r, ngx_str_t *realm);

static ngx_int_t ngx_http_auth_wsse_username_pwd(ngx_http_request_t *r, ngx_http_auth_wsse_fields_t *auth_fields);
static ngx_int_t ngx_http_auth_wsse_get_wsse(ngx_http_request_t *r, ngx_str_t *wsse);
static ngx_int_t ngx_http_auth_wsse_parse(ngx_http_request_t *r, ngx_str_t *wsse, ngx_http_auth_wsse_fields_t *auth_fields);
static ngx_int_t ngx_http_auth_wsse_verify_user(ngx_http_request_t *r, ngx_http_auth_wsse_fields_t *auth_fields);
static ngx_int_t ngx_http_auth_wsse_verify_digest(ngx_http_request_t *r, ngx_str_t *pw_digest, ngx_http_auth_wsse_fields_t *auth_fields);

static ngx_int_t ngx_http_auth_wsse_init(ngx_conf_t *cf);
static void *ngx_http_auth_wsse_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_wsse_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_command_t ngx_http_auth_wsse_commands[] = {

    {
        ngx_string("auth_wsse"),
        NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF |
        NGX_HTTP_LMT_CONF | NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot, NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_auth_wsse_loc_conf_t, realm), NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_wsse_module_ctx = {
    NULL,                    /* preconfiguration */
    ngx_http_auth_wsse_init, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_auth_wsse_create_loc_conf, /* create location configuration */
    ngx_http_auth_wsse_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_auth_wsse_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_wsse_module_ctx, /* module context */
    ngx_http_auth_wsse_commands,    /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};

/*
     token          = 1*<any CHAR except CTLs or separators>
     separators     = "(" | ")" | "<" | ">" | "@"
                    | "," | ";" | ":" | "\" | <">
                    | "/" | "[" | "]" | "?" | "="
                    | "{" | "}" | SP | HT
  */

static uint32_t token_char[] = {
    0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

    /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
    0x03ff6cf8, /* 0000 0011 1111 1111  0110 1100 1111 1000 */

    /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
    0xc7fffffe, /* 1100 0111 1111 1111  1111 1111 1111 1110 */

    /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
    0x57ffffff, /* 0101 0111 1111 1111  1111 1111 1111 1111 */

    0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
    0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
    0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
    0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
};

static ngx_inline void ngx_http_auth_wsse_evasion_tracking(ngx_http_request_t *r,
        ngx_http_auth_wsse_loc_conf_t *alcf,
        ngx_int_t status)
{
    if(status == NGX_HTTP_AUTH_WSSE_STATUS_SUCCESS) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "successful auth, clearing evasion counters");

    } else {
        // Reset the failure count to 1 if we're outside the evasion window
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "failed auth, updating evasion counters");
    }
}

static ngx_int_t ngx_http_auth_wsse_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_str_t realm;
    ngx_http_auth_wsse_loc_conf_t *alcf;
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_wsse_module);

    if(alcf->realm == NULL) {
        return NGX_DECLINED;
    }

    if(ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "ngx_http_complex_value realm failed");
        return NGX_ERROR;
    }

    if(realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "ngx_http_complex_value realm off");
        return NGX_DECLINED;
    }

    ngx_http_auth_wsse_fields_t *auth_fields =
        ngx_pcalloc(r->pool, sizeof(ngx_http_auth_wsse_fields_t));

    if(!auth_fields) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // 进行认证
    rc = ngx_http_auth_wsse_username_pwd(r, auth_fields);

    if(rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "no user/password was provided for wsse authentication");
        return ngx_http_auth_wsse_set_realm(r, &realm);
    }

    if(rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_auth_wsse_verify_user(r, auth_fields);

    if(rc != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "ngx_http_auth_wsse_verify_user %i", rc);
        ngx_http_auth_wsse_evasion_tracking(r, alcf, NGX_HTTP_AUTH_WSSE_STATUS_FAILURE);
        return ngx_http_auth_wsse_set_realm(r, &realm);
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_auth_wsse_set_realm(ngx_http_request_t *r,
        ngx_str_t *realm)
{
    size_t len;
    u_char *wsse;
    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);

    if(r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.date = ngx_list_push(&r->headers_out.headers);

    if(r->headers_out.date == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("WSSE realm=\"\",profile=\"UsernamePwd\"") - 1 + realm->len;
    wsse = ngx_pnalloc(r->pool, len);

    if(wsse == NULL) {
        r->headers_out.www_authenticate->hash = 0;
        r->headers_out.www_authenticate = NULL;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_snprintf(wsse, len, "WSSE realm=\"%V\",profile=\"UsernamePwd\"", realm);
    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = wsse;
    r->headers_out.www_authenticate->value.len = len;
    // hemu wsse认证要求
    ngx_time_update();
    r->headers_out.date->hash = 2;
    ngx_str_set(&r->headers_out.date->key, "Date");
    r->headers_out.date->value.data = ngx_cached_http_log_iso8601.data;
    r->headers_out.date->value.len = ngx_cached_http_log_iso8601.len;
    return NGX_HTTP_UNAUTHORIZED;
}

static ngx_int_t ngx_http_auth_wsse_get_wsse(ngx_http_request_t *r, ngx_str_t *wsse)
{
    ngx_uint_t i;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    part = &r->headers_in.headers.part;
    header = part->elts;

    for(i = 0; /* void */; i++) {
        if(i >= part->nelts) {
            if(part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if(header[i].hash == 0) {
            // 不合法的头部
            continue;
        }

        if(0 == ngx_strncasecmp(header[i].key.data, (u_char *)"X-WSSE",
                                header[i].key.len)) {
            wsse->data = header[i].value.data;
            wsse->len = header[i].value.len;
            return NGX_OK;
        }
    }

    return NGX_ERROR;
}

static ngx_int_t ngx_http_auth_wsse_parse(ngx_http_request_t *r, ngx_str_t *wsse,
        ngx_http_auth_wsse_fields_t *auth_fields)
{
    u_char ch, *p, *last, *start = 0, *end;
    enum {
        sw_start = 0,
        sw_scheme,
        sw_scheme_end,
        sw_lws_start,
        sw_lws,
        sw_param_name_start,
        sw_param_name,
        sw_param_value_start,
        sw_param_value,
        sw_param_quoted_value,
        sw_param_end,
        sw_error,
    } state;
    state = sw_start;
    p = wsse->data;
    last = wsse->data + wsse->len;
    ch = *p++;
    ngx_str_t name = ngx_null_string, value = ngx_null_string;
    ngx_int_t comma_count = 0, quoted_pair_count = 0;
    uint32_t in_value;

    while(p <= last) {
        switch(state) {
            case sw_error:
            default:
                return NGX_DECLINED;

            /* first char */
            case sw_start:
                if(ch == CR || ch == LF || ch == ' ' || ch == '\t') {
                    ch = *p++;

                } else if(token_char[ch >> 5] & (1 << (ch & 0x1f))) {
                    start = p - 1;
                    state = sw_scheme;

                } else {
                    state = sw_error;
                }

                break;

            case sw_scheme:
                if(token_char[ch >> 5] & (1 << (ch & 0x1f))) {
                    ch = *p++;

                } else if(ch == ' ') {
                    end = p - 1;
                    state = sw_scheme_end;
                    auth_fields->schema.data = start;
                    auth_fields->schema.len = end - start;

                    if(ngx_strncasecmp(auth_fields->schema.data, (u_char *)"UsernamePwd",
                                       auth_fields->schema.len) != 0) {
                        state = sw_error;
                    }

                } else {
                    state = sw_error;
                }

                break;

            case sw_scheme_end:
                if(ch == ' ') {
                    ch = *p++;

                } else {
                    state = sw_param_name_start;
                }

                break;

            case sw_param_name_start:
                if(token_char[ch >> 5] & (1 << (ch & 0x1f))) {
                    start = p - 1;
                    state = sw_param_name;
                    ch = *p++;

                } else {
                    state = sw_error;
                }

                break;

            case sw_param_name:
                if(token_char[ch >> 5] & (1 << (ch & 0x1f))) {
                    ch = *p++;

                } else if(ch == '=') {
                    end = p - 1;
                    state = sw_param_value_start;
                    name.data = start;
                    name.len = end - start;
                    ch = *p++;

                } else {
                    state = sw_error;
                }

                break;

            case sw_param_value_start:
                if(token_char[ch >> 5] & (1 << (ch & 0x1f))) {
                    start = p - 1;
                    state = sw_param_value;
                    ch = *p++;

                } else if(ch == '\"') {
                    start = p;
                    quoted_pair_count = 0;
                    state = sw_param_quoted_value;
                    ch = *p++;

                } else {
                    state = sw_error;
                }

                break;

            case sw_param_value:
                in_value = token_char[ch >> 5] & (1 << (ch & 0x1f));

                if(in_value) {
                    ch = *p++;
                }

                if(!in_value || p > last) {
                    end = p - 1;
                    value.data = start;
                    value.len = end - start;
                    state = sw_param_end;
                    goto param_end;
                }

                break;

            case sw_param_quoted_value:
                if(ch < 0x20 || ch == 0x7f) {
                    state = sw_error;

                } else if(ch == '\\' && *p <= 0x7f) {
                    quoted_pair_count++;
                    /* Skip the next char, even if it's a \ */
                    ch = *(p += 2);

                } else if(ch == '\"') {
                    end = p - 1;
                    ch = *p++;
                    value.data = start;
                    value.len = end - start - quoted_pair_count;

                    if(quoted_pair_count > 0) {
                        value.data = ngx_palloc(r->pool, value.len);
                        u_char *d = value.data;
                        u_char *s = start;

                        for(; s < end; s++) {
                            ch = *s;

                            if(ch == '\\') {
                                /* Make sure to add the next character
                                 * even if it's a \
                                 */
                                s++;

                                if(s < end) {
                                    *d++ = ch;
                                }

                                continue;
                            }

                            *d++ = ch;
                        }
                    }

                    state = sw_param_end;
                    goto param_end;

                } else {
                    ch = *p++;
                }

                break;
param_end:

            case sw_param_end:
                if(ngx_strncasecmp(name.data, (u_char *)"Username", name.len) == 0) {
                    auth_fields->username = value;

                } else if(ngx_strncasecmp(name.data, (u_char *)"PasswordDigest",
                                          name.len) == 0) {
                    auth_fields->pw_digest = value;

                } else if(ngx_strncasecmp(name.data, (u_char *)"Nonce", name.len) == 0) {
                    auth_fields->nonce = value;

                } else if(ngx_strncasecmp(name.data, (u_char *)"Created", name.len) ==
                          0) {
                    auth_fields->created = value;

                } else {
                    ngx_log_error(NGX_LOG_WARN, ngx_cycle->log, 0, "unexcpet %V", &name);
                }

                state = sw_lws_start;
                break;

            case sw_lws_start:
                comma_count = 0;
                state = sw_lws;
                break;

            /* fall through */
            case sw_lws:
                if(comma_count > 0 && (token_char[ch >> 5] & (1 << (ch & 0x1f)))) {
                    state = sw_param_name_start;

                } else if(ch == ',') {
                    comma_count++;
                    ch = *p++;

                } else if(ch == CR || ch == LF || ch == ' ' || ch == '\t') {
                    ch = *p++;

                } else {
                    state = sw_error;
                }

                break;
        } // end switch
    }   // end while

    if(state != sw_lws_start && state != sw_lws) {
        return NGX_DECLINED;
    }

    // bail out if anything but the opaque field is missing from the request
    // header

    if(!(auth_fields->username.len > 0 && auth_fields->pw_digest.len > 0 &&
         auth_fields->nonce.len > 0 && auth_fields->created.len > 0) ||
       (auth_fields->nonce.len != 16)) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_auth_wsse_verify_user(ngx_http_request_t *r,
        ngx_http_auth_wsse_fields_t *auth_fields)
{
    ngx_uint_t nomatch = 0;
    ngx_str_t password;

    // 查找用户名, 找不到用户nomatch=1
    if(nomatch) {
        return NGX_HTTP_AUTH_WSSE_USERNOTFOUND;
    }

    // 未获取用户对应的密码，此处可以参考ngx-http-auth-digest-modules
    ngx_str_set(&password, "123456");
    return ngx_http_auth_wsse_verify_digest(r, &password, auth_fields);
}

static ngx_int_t ngx_http_auth_wsse_verify_digest(ngx_http_request_t *r, ngx_str_t *password,
        ngx_http_auth_wsse_fields_t *auth_fields)
{
    size_t len;
    ngx_str_t encoded, decoded;
    u_char digest[20], *encrypted;
    ngx_sha1_t sha1;
    decoded.len = sizeof(digest);
    decoded.data = digest;
    len = ngx_base64_encoded_length(decoded.len) + 1;
    encrypted = ngx_pnalloc(r->pool, len);

    if(encrypted == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_sha1_init(&sha1);
    ngx_sha1_update(&sha1, auth_fields->nonce.data, auth_fields->nonce.len);
    ngx_sha1_update(&sha1, auth_fields->created.data, auth_fields->created.len);
    ngx_sha1_update(&sha1, password->data, password->len);
    ngx_sha1_final(digest, &sha1);
    encoded.data = encrypted;
    encoded.len = len;
    ngx_encode_base64(&encoded, &decoded);
    encoded.data[encoded.len] = '\0';

    // compare the hash of the full digest string to the response field of the
    // auth header
    // and bail out if they don't match

    if(encoded.len != auth_fields->pw_digest.len ||
       ngx_memcmp(encoded.data, auth_fields->pw_digest.data, auth_fields->pw_digest.len) != 0) {
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "%z %z", encoded.len, auth_fields->pw_digest.len);
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "%V", &encoded);
        ngx_log_error(NGX_LOG_DEBUG, ngx_cycle->log, 0, "%V", &auth_fields->pw_digest);
        return NGX_ERROR;
    }

    // 增加nonce过期校验，防止重放
    return NGX_OK;
}

static ngx_int_t ngx_http_auth_wsse_username_pwd(ngx_http_request_t *r,
        ngx_http_auth_wsse_fields_t *auth_fields)
{
    ngx_int_t rc;
    ngx_str_t auth, wsse;
    //    ngx_uint_t  len;

    if(r->headers_in.user.len == 0 && r->headers_in.user.data != NULL) {
        return NGX_DECLINED;
    }

    if(r->headers_in.authorization == NULL) {
        r->headers_in.user.data = (u_char *)"";
        return NGX_DECLINED;
    }

    auth = r->headers_in.authorization->value;

    if(auth.len < sizeof("WSSE profile=\"UsernamePwd\"") - 1 ||
       ngx_strncasecmp(auth.data, (u_char *)"WSSE profile=\"UsernamePwd\"",
                       sizeof("WSSE profile=\"UsernamePwd\"") - 1) != 0) {
        r->headers_in.user.data = (u_char *)"";
        return NGX_DECLINED;
    }

    // 获取X-WSSE头部值

    if(NGX_OK != ngx_http_auth_wsse_get_wsse(r, &wsse)) {
        r->headers_in.user.data = (u_char *)"";
        return NGX_DECLINED;
    }

    // 解析X-WSSE头部值
    rc = ngx_http_auth_wsse_parse(r, &wsse, auth_fields);

    if(rc == NGX_DECLINED) {
        return NGX_DECLINED;

    } else if(rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return rc;
}

static ngx_int_t ngx_http_auth_wsse_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if(h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_wsse_handler;
    return NGX_OK;
}

static void *ngx_http_auth_wsse_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_wsse_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_wsse_loc_conf_t));

    if(conf == NULL) {
        return NULL;
    }

    return conf;
}

static char *ngx_http_auth_wsse_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child)
{
    ngx_http_auth_wsse_loc_conf_t *prev = parent;
    ngx_http_auth_wsse_loc_conf_t *conf = child;

    if(conf->realm == NULL) {
        conf->realm = prev->realm;
    }

    return NGX_CONF_OK;
}

/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_test_ref_module -- the reference consumer of the test probe.
 *
 * This module exists so CI can BOOT a server and run the scenario tree. The
 * probe and the prober were both fully built and fully unexercised: every job
 * compiled the probe, none ever linked it into a server and made a request to
 * it, because prober_resolve requires a PROBER_MODULE and this repo shipped
 * none. Layer 3 -- scenarios, drivers, signal choreography -- had no execution
 * anywhere. Shipping the first drivers on top of that is how the s43
 * flaky-fork bug nearly merged.
 *
 * It is deliberately the SMALLEST module that makes the existing scenarios
 * runnable, and it is not a demonstration of the hook API. Both hooks in
 * ngx_test_probe_hooks_t are optional; a module registering neither still gets
 * the whole generic document -- flavor, pid, connections, fds, cycle-pool
 * accounting -- and that generic half is exactly what all 13 checked-in
 * scenarios assert on (`delta fds`, `delta pool.cycle_used`, and the http
 * behaviour around them). Registering a zone_render or a fault_set here would
 * add surface that nothing in the tree reads, and would make this module a
 * second, subtly different reference for consumers to copy from. The hooks are
 * documented in the header and exercised by the direct-call unit harness in
 * t/; that is where they belong.
 *
 * For the same reason it takes no shm zone. `test_ref_probe;` is the whole
 * directive, PROBER_PROBE_ZONE stays empty, and the probe reports
 * "zone": {"present": false} -- which is a legitimate rendering, not a
 * degraded one, and one no scenario currently discriminates on.
 *
 * A consuming module (shield, and whatever follows) is the real integration
 * test of the hook API. This one only has to prove the harness can drive a
 * live server end to end.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_test_probe.h"

#ifndef NGX_TEST_HARNESS
#error "ngx_http_test_ref_module is a CI-only module and requires NGX_TEST_HARNESS"
#endif

static char *ngx_http_test_ref_probe(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_test_ref_handler(ngx_http_request_t *r);


static ngx_command_t  ngx_http_test_ref_commands[] = {

    /*
     * NGX_CONF_NOARGS: this module takes no zone, so the directive that the
     * scenario confs put in `location /__probe` is bare. A consumer whose
     * probe needs a zone declares its own directive with its own argument
     * spec -- @PROBE@ exists precisely so the scenario tree does not have to
     * know which shape it is.
     */
    { ngx_string("test_ref_probe"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_test_ref_probe,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_test_ref_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */
    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */
    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */
    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


ngx_module_t  ngx_http_test_ref_module = {
    NGX_MODULE_V1,
    &ngx_http_test_ref_module_ctx, /* module context */
    ngx_http_test_ref_commands,    /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_test_ref_probe(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_test_ref_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_test_ref_handler(ngx_http_request_t *r)
{
    u_char       *last;
    size_t        len;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;
    u_char        buf[NGX_TEST_PROBE_JSON_MAX];

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /*
     * Discard the request body before answering. Skipping this leaves an
     * unread body in the connection buffer, which the next request on a
     * keepalive connection then parses as its request line -- and
     * keepalive-bleed is one of the checked-in scenarios.
     */
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    /*
     * Fault arming happens before rendering, so a request that both arms a
     * fault and reads the document sees the state it just asked for. Return
     * value is deliberately ignored: NGX_DECLINED means "no fault directive in
     * this query, or no fault_set hook" -- this module registers none, so that
     * is the normal answer here and not an error. The probe validates the
     * argument itself; a malformed one arms nothing.
     */
    (void) ngx_test_probe_arm(NULL, &r->args);

    last = ngx_test_probe_json(buf, buf + sizeof(buf), NULL);
    len = (size_t) (last - buf);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) len;

    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_lowcase = NULL;

    if (r->method == NGX_HTTP_HEAD) {
        return ngx_http_send_header(r);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(b->pos, buf, len);
    b->last = b->pos + len;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}

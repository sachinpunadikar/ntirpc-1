/*
  authgss_prot.c

  Copyright (c) 2000 The Regents of the University of Michigan.
  All rights reserved.

  Copyright (c) 2000 Dug Song <dugsong@UMICH.EDU>.
  All rights reserved, all wrongs reversed.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
  3. Neither the name of the University nor the names of its
  contributors may be used to endorse or promote products derived
  from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <rpc/types.h>
#include <rpc/xdr_inline.h>
#include <rpc/auth_inline.h>
#include <rpc/auth.h>
#include <rpc/auth_gss.h>
#include <rpc/rpc.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

/* additional space needed for encoding */
#define RPC_SLACK_SPACE 1024
#define AUTHGSS_MAX_TOKEN_SIZE 24576 /* default MS PAC is 12000 bytes */
#define MAXALLOCA (256)

bool
xdr_rpc_gss_encode(XDR *xdrs, gss_buffer_t buf, u_int maxsize)
{
	u_int tmplen = buf->length;
	bool xdr_stat;

	if (buf->length > UINT_MAX)
		return FALSE;

	xdr_stat = xdr_bytes_encode(xdrs, (char **)&buf->value, &tmplen,
					   maxsize);

	__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS, "%s() %s (%p:%d)",
		__func__,
		(xdr_stat == TRUE) ? "success" : "failure",
		buf->value, buf->length);

	return xdr_stat;
}

bool
xdr_rpc_gss_decode(XDR *xdrs, gss_buffer_t buf)
{
	u_int tmplen = 0;
	bool xdr_stat;

	xdr_stat = xdr_bytes_decode(xdrs, (char **)&buf->value, &tmplen,
					   UINT_MAX);

	if (xdr_stat)
		buf->length = tmplen;

	__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS, "%s() %s (%p:%d)",
		__func__,
		(xdr_stat == TRUE) ? "success" : "failure",
		buf->value, buf->length);

	return xdr_stat;
}

static bool
xdr_rpc_gss_buf(XDR *xdrs, gss_buffer_t buf, u_int maxsize)
{
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		return (xdr_rpc_gss_encode(xdrs, buf, maxsize));
	case XDR_DECODE:
		return (xdr_rpc_gss_decode(xdrs, buf));
	case XDR_FREE:
		return (TRUE);
	};
	return (FALSE);
}

bool
xdr_rpc_gss_cred(XDR *xdrs, struct rpc_gss_cred *p)
{
	bool xdr_stat;

	xdr_stat = (inline_xdr_u_int32_t(xdrs, &p->gc_v)
		    && inline_xdr_enum(xdrs, (enum_t *) &p->gc_proc)
		    && inline_xdr_u_int32_t(xdrs, &p->gc_seq)
		    && inline_xdr_enum(xdrs, (enum_t *) &p->gc_svc)
		    && xdr_rpc_gss_buf(xdrs, &p->gc_ctx, MAX_AUTH_BYTES));

	__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
		"%s() %s %s (v %" PRIu32 ", proc %" PRIu32 ", seq %" PRIu32 ", svc %" PRIu32 ", ctx %p:%d)",
		__func__,
		(xdrs->x_op == XDR_ENCODE) ? "encode" : "decode",
		(xdr_stat == TRUE) ? "success" : "failure",
		p->gc_v, p->gc_proc, p->gc_seq, p->gc_svc,
		p->gc_ctx.value, p->gc_ctx.length);

	return (xdr_stat);
}

bool
xdr_rpc_gss_init_args(XDR *xdrs, gss_buffer_desc *p)
{
	bool xdr_stat;
	u_int maxlen = AUTHGSS_MAX_TOKEN_SIZE;

	xdr_stat = xdr_rpc_gss_buf(xdrs, p, maxlen);

	__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS, "%s() %s %s (token %p:%d)",
		__func__,
		(xdrs->x_op == XDR_ENCODE) ? "encode" : "decode",
		(xdr_stat == TRUE) ? "success" : "failure",
		p->value, p->length);

	return (xdr_stat);
}

bool
xdr_rpc_gss_init_res(XDR *xdrs, struct rpc_gss_init_res *p)
{
	bool xdr_stat;

	u_int ctx_maxlen = (u_int) (p->gr_ctx.length + RPC_SLACK_SPACE);
	u_int tok_maxlen = (u_int) (p->gr_token.length + RPC_SLACK_SPACE);

	xdr_stat = (xdr_rpc_gss_buf(xdrs, &p->gr_ctx, ctx_maxlen)
		    && inline_xdr_u_int32_t(xdrs, &p->gr_major)
		    && inline_xdr_u_int32_t(xdrs, &p->gr_minor)
		    && inline_xdr_u_int32_t(xdrs, &p->gr_win)
		    && xdr_rpc_gss_buf(xdrs, &p->gr_token, tok_maxlen));

	__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
		"%s() %s %s (ctx %p:%d, maj %" PRIu32 ", min %" PRIu32 ", win %" PRIu32 ", token %p:%d)",
		__func__,
		(xdrs->x_op == XDR_ENCODE) ? "encode" : "decode",
		(xdr_stat == TRUE) ? "success" : "failure",
		p->gr_ctx.value, p->gr_ctx.length,
		p->gr_major, p->gr_minor, p->gr_win,
		p->gr_token.value, p->gr_token.length);

	return (xdr_stat);
}

bool
xdr_rpc_gss_wrap(XDR *xdrs, xdrproc_t xdr_func, void *xdr_ptr,
		 gss_ctx_id_t ctx, gss_qop_t qop, rpc_gss_svc_t svc, u_int seq)
{
	gss_buffer_desc databuf, wrapbuf;
	OM_uint32 maj_stat, min_stat;
	int start, end, conf_state, iov_count, data_count, after_data, i;
	bool xdr_stat, vector;
	u_int databuflen, maxwrapsz;
	gss_iov_buffer_desc *gss_iov;
	xdr_vio *xdr_iov, *data;
	u_int32_t xvsize = 0, gvsize = 0;

	if (svc != RPCSEC_GSS_SVC_PRIVACY &&
	    svc != RPCSEC_GSS_SVC_INTEGRITY) {
		/* For some reason we got here with not supported type. */
		return (FALSE);
	}

	/* Write dummy for databody length. The length will be filled in later.
	 * - For RPCSEC_GSS_SVC_PRIVACY the length will include the whole
	 *   result of gss_wrap.
	 * - For RPCSEC_GSS_SVC_INTEGRITY the length will just be the response
	 *   data length.
	 * No matter what type or how we process, we will come back and fill
	 * the length in exactly here.
	 */
	start = XDR_GETPOS(xdrs);
	databuflen = 0xaaaaaaaa;	/* should always overwrite */
	if (!XDR_PUTUINT32(xdrs, databuflen))
		return (FALSE);

	/* Determine if XDR is a vector or not.
	 * If it's a vector, a new buffer has been allocated.
	 */
	vector = XDR_NEWBUF(xdrs);

	/* Marshal rpc_gss_data_t (sequence number + arguments).
	 * If it's a vector, the response has been marshalled into a new
	 * buffer so that we will be able to insert any header.
	 */
	if (!XDR_PUTUINT32(xdrs, seq) || !(*xdr_func) (xdrs, xdr_ptr))
		return (FALSE);
	end = XDR_GETPOS(xdrs);
	databuflen = end - start - 4;

	if (vector) {
		/* Now we have the response encoded, time to build out iov for
		 * gss_get_mic_iov or gss_wrap_iov.
		 *
		 * vsize = ioq count + 2 (for header and trailer)
		 */
		data_count = XDR_IOVCOUNT(xdrs, start + 4);

		if (data_count < 0)
			return (FALSE);

		if (svc == RPCSEC_GSS_SVC_INTEGRITY) {
			/* Add a trailer buffer for the MIC */
			iov_count = data_count + 1;
			after_data = data_count;
		} else if (svc == RPCSEC_GSS_SVC_PRIVACY) {
			/* Add header, padding, and trailer for the wrap */
			iov_count = data_count + 3;
			after_data = data_count + 1;
		}

		/* Determine the size of the gss_iov */
		gvsize = iov_count * sizeof(gss_iov_buffer_desc);
		xvsize = iov_count * sizeof(xdr_vio);

		/* Allocate the gss_iov */
		if (unlikely(gvsize > MAXALLOCA)) {
			gss_iov = mem_alloc(gvsize);
		} else {
			gss_iov = alloca(gvsize);
		}

		/* Allocate the xdr_iov */
		if (unlikely(xvsize > MAXALLOCA)) {
			xdr_iov = mem_alloc(xvsize);
		} else {
			xdr_iov = alloca(xvsize);
		}

		memset(gss_iov, 0, gvsize);
		memset(xdr_iov, 0, xvsize);

		/* Point to where the first buffer in the data will be. */
		data = &xdr_iov[(svc == RPCSEC_GSS_SVC_PRIVACY) ? 1 : 0];

		/* Now fill in the data buffers
		 * vector is empty on entry
		 * DATA buffers are completely filled (vio_base, vio_head,
		 *   vio_tail, vio_wrap, vio_length, and vio_type) on exit.
		 * No other buffers are touched at this point.
		 */
		xdr_stat = XDR_FILLBUFS(xdrs, start + 4, data);

		/* Now set up the gss_iov */
		for (i = 0; i < iov_count; i++) {
			if (i == 0 && svc == RPCSEC_GSS_SVC_PRIVACY) {
				/* Fill in HEADER buffer */
				gss_iov[i].type = GSS_IOV_BUFFER_TYPE_HEADER;
			} else if (i < after_data) {
				/* Copy over a DATA buffer */
				gss_iov[i].type = GSS_IOV_BUFFER_TYPE_DATA;
				gss_iov[i].buffer.length =
							xdr_iov[i].vio_length;
				gss_iov[i].buffer.value =
							xdr_iov[i].vio_head;
			} else if (svc == RPCSEC_GSS_SVC_INTEGRITY) {
				/* Set up TRAILER buffer for INTEGRITY*/
				gss_iov[i].type = GSS_IOV_BUFFER_TYPE_TRAILER;
			} else if (i == after_data) {
				/* Set up PADDING buffer for PRIVACY*/
				gss_iov[i].type = GSS_IOV_BUFFER_TYPE_PADDING;
			} else {
				/* Set up TRAILER buffer for PRIVACY*/
				gss_iov[i].type = GSS_IOV_BUFFER_TYPE_TRAILER;
			}
		}

		/* At this point gss_iov HEADER, PADDING, and TRAILER have
		 * type set and buffer is empty.
		 * DATA is completely filled in.
		 * xdr_iov DATA buffers are completely filled in.
		 * xdr_iov HEADER and TRAILER buffers are empty.
		 */

		if (svc == RPCSEC_GSS_SVC_INTEGRITY) {
			/* Now call gss_get_mic_iov_length */
			maj_stat = gss_get_mic_iov_length(&min_stat, ctx, qop,
							  gss_iov, iov_count);

			if (maj_stat != GSS_S_COMPLETE) {
				__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
					"%s() gss_get_mic_iov_length failed",
					__func__);
				xdr_stat = FALSE;
				goto out;
			}

			/* Copy the TRAILER buffer length into the xdr_iov */
			xdr_iov[after_data].vio_length =
				gss_iov[after_data].buffer.length;
			xdr_iov[after_data].vio_type = VIO_TRAILER;

			/* Marshal databody_integ length. Note tha this will
			 * leave the cursor position at start + 4 but the
			 * forthcoming XDR_ALLOCHDRS is going to fix the
			 * cursor position to the end of everything.
			 */
			if (!XDR_SETPOS(xdrs, start)) {
				__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
					"%s() XDR_SETPOS #2 failed",
					__func__);
				return (FALSE);
			}

			if (!XDR_PUTUINT32(xdrs, databuflen))
				return (FALSE);
		} else {
			u_int databody_priv_len;

			/* Now call gss_wrap_iov_length */
			maj_stat = gss_wrap_iov_length(&min_stat, ctx, true,
						       qop, GSS_C_QOP_DEFAULT,
						       gss_iov, iov_count);

			if (maj_stat != GSS_S_COMPLETE) {
				__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
					"%s() gss_wrap_iov_length failed",
					__func__);
				xdr_stat = FALSE;
				goto out;
			}

			/* Copy the HEADER buffer length into the xdr_iov */
			xdr_iov[0].vio_length = gss_iov[0].buffer.length;
			xdr_iov[0].vio_type = VIO_HEADER;

			/* Copy the PADDING buffer length into the xdr_iov */
			xdr_iov[after_data].vio_length =
				gss_iov[after_data].buffer.length;
			xdr_iov[after_data].vio_type = VIO_TRAILER;

			/* Copy the TRAILER buffer length into the xdr_iov */
			xdr_iov[after_data + 1].vio_length =
				gss_iov[after_data + 1].buffer.length;
			xdr_iov[after_data + 1].vio_type = VIO_TRAILER;

			/* Compute the databody_priv length as sum of
			 * the databuflen and the HEADER, PADDING, and
			 * TRAILER buffers.
			 */
			databody_priv_len = databuflen +
					gss_iov[0].buffer.length +
					gss_iov[after_data].buffer.length +
					gss_iov[after_data + 1].buffer.length;

			/* Marshal databody_priv length. Note tha this will
			 * leave the cursor position at start + 4 but the
			 * forthcoming XDR_ALLOCHDRS is going to fix the
			 * cursor position to the end of everything.
			 */
			if (!XDR_SETPOS(xdrs, start)) {
				__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
					"%s() XDR_SETPOS #2 failed",
					__func__);
				return (FALSE);
			}

			if (!XDR_PUTUINT32(xdrs, databody_priv_len))
				return (FALSE);
		}

		/* At this point:
		 * The xdr_iov DATA buffers are completely filled in.
		 * The xdr_iov HEADER and TRAILER buffers have type and length
		 *   filled in.
		 */

		/* Now actually allocate the HEADER, PADDING, and TRAILER.
		 * The cursor position will be updated to the end of the
		 * TRAILER.
		 */
		xdr_stat = XDR_ALLOCHDRS(xdrs, start + 4, xdr_iov, iov_count);

		if (!xdr_stat)
			goto out;

		/* At this point the xdr_iov is completely filled in. */

		if (svc == RPCSEC_GSS_SVC_INTEGRITY) {
			/* Copy the TRAILER buffer into the gss_iov */
			gss_iov[after_data].buffer.value =
				xdr_iov[after_data].vio_head;

			/* At this point the gss_iov is completely filled in */

			/* Now call gss_get_mic_iov */
			maj_stat = gss_get_mic_iov(&min_stat, ctx, qop,
						   gss_iov, iov_count);

			if (maj_stat != GSS_S_COMPLETE) {
				__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
					"%s() gss_get_mic_iov failed",
					__func__);
				xdr_stat = FALSE;
				goto out;
			}
		} else {
			/* Copy the HEADER buffer into the gss_iov */
			gss_iov[0].buffer.value = xdr_iov[0].vio_head;

			/* Copy the PADDING buffer into the gss_iov */
			gss_iov[after_data].buffer.value =
				xdr_iov[after_data].vio_head;

			/* Copy the TRAILER buffer into the gss_iov */
			gss_iov[after_data + 1].buffer.value =
				xdr_iov[after_data + 1].vio_head;

			/* At this point the gss_iov is completely filled in */

			/* Now call gss_wrap_iov */
			maj_stat = gss_wrap_iov(&min_stat, ctx, true,
						GSS_C_QOP_DEFAULT, NULL,
						gss_iov, iov_count);

			if (maj_stat != GSS_S_COMPLETE) {
				__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
					"%s() gss_wrap_iov failed",
					__func__);
				xdr_stat = FALSE;
				goto out;
			}
		}

		/* At this point, the xdr_iov now has all the GSS data in it
		 * and wrapping is complete. Now we need to go back and write
		 * the length back at start.
		 */

		goto out;
	} /* else fall through to legacy single buffer implementation */

	/* Initialize the static buffers */
	memset(&databuf, 0, sizeof(databuf));
	memset(&wrapbuf, 0, sizeof(wrapbuf));

	/* Set databuf to marshalled rpc_gss_data_t. */
	if (!XDR_SETPOS(xdrs, start+4)) {
		__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
			"%s() XDR_SETPOS #1 failed",
			__func__);
		return (FALSE);
	}
	databuf.length = databuflen;
	databuf.value = xdr_inline_encode(xdrs, databuflen);

	if (!databuf.value) {
		__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
			"%s() xdr_inline_encode failed",
			__func__);
		return (FALSE);
	}

	xdr_stat = FALSE;

	if (svc == RPCSEC_GSS_SVC_INTEGRITY) {
		/* Marshal databody_integ length. */
		if (!XDR_SETPOS(xdrs, start)) {
			__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
				"%s() XDR_SETPOS #2 failed",
				__func__);
			return (FALSE);
		}
		if (!XDR_PUTUINT32(xdrs, databuflen))
			return (FALSE);

		/* Checksum rpc_gss_data_t. */
		maj_stat = gss_get_mic(&min_stat, ctx, qop, &databuf, &wrapbuf);
		if (maj_stat != GSS_S_COMPLETE) {
			__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
				"%s() gss_get_mic failed",
				__func__);
			return (FALSE);
		}
		/* Marshal checksum. */
		if (!XDR_SETPOS(xdrs, end)) {
			__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
				"%s() XDR_SETPOS #3 failed",
				__func__);
			gss_release_buffer(&min_stat, &wrapbuf);
			return (FALSE);
		}
		maxwrapsz = (u_int) (wrapbuf.length + RPC_SLACK_SPACE);
		xdr_stat = xdr_rpc_gss_encode(xdrs, &wrapbuf, maxwrapsz);
		gss_release_buffer(&min_stat, &wrapbuf);
	} else if (svc == RPCSEC_GSS_SVC_PRIVACY) {
		/* Encrypt rpc_gss_data_t. */
		maj_stat =
		    gss_wrap(&min_stat, ctx, TRUE, qop, &databuf, &conf_state,
			     &wrapbuf);
		if (maj_stat != GSS_S_COMPLETE) {
			gss_log_status("gss_wrap", maj_stat, min_stat);
			return (FALSE);
		}
		/* Marshal databody_priv. */
		if (!XDR_SETPOS(xdrs, start)) {
			__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
				"%s() XDR_SETPOS #4 failed",
				__func__);
			gss_release_buffer(&min_stat, &wrapbuf);
			return (FALSE);
		}
		maxwrapsz = (u_int) (wrapbuf.length + RPC_SLACK_SPACE);
		xdr_stat = xdr_rpc_gss_encode(xdrs, &wrapbuf, maxwrapsz);
		gss_release_buffer(&min_stat, &wrapbuf);
	}
	if (!xdr_stat) {
		__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS, "%s() failed", __func__);
	}

out:

	if (unlikely(gvsize > MAXALLOCA)) {
		mem_free(gss_iov, gvsize);
	}

	if (unlikely(xvsize > MAXALLOCA)) {
		mem_free(xdr_iov, xvsize);
	}

	return (xdr_stat);
}

bool
xdr_rpc_gss_unwrap(XDR *xdrs, xdrproc_t xdr_func, void *xdr_ptr,
		   gss_ctx_id_t ctx, gss_qop_t qop, rpc_gss_svc_t svc,
		   u_int seq)
{
	XDR tmpxdrs;
	gss_buffer_desc databuf, wrapbuf;
	OM_uint32 maj_stat, min_stat;
	u_int qop_state;
	int conf_state;
	uint32_t seq_num;
	bool xdr_stat;

	if (xdr_func == (xdrproc_t) xdr_void || xdr_ptr == NULL)
		return (TRUE);

	memset(&databuf, 0, sizeof(databuf));
	memset(&wrapbuf, 0, sizeof(wrapbuf));

	if (svc == RPCSEC_GSS_SVC_INTEGRITY) {
		/* Decode databody_integ. */
		if (!xdr_rpc_gss_decode(xdrs, &databuf)) {
			__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
				"%s() xdr_rpc_gss_decode databody_integ failed",
				__func__);
			return (FALSE);
		}
		/* Decode checksum. */
		if (!xdr_rpc_gss_decode(xdrs, &wrapbuf)) {
			gss_release_buffer(&min_stat, &databuf);
			__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
				"%s() xdr_rpc_gss_decode checksum failed",
				__func__);
			return (FALSE);
		}
		/* Verify checksum and QOP. */
		maj_stat =
		    gss_verify_mic(&min_stat, ctx, &databuf, &wrapbuf,
				   &qop_state);
		gss_release_buffer(&min_stat, &wrapbuf);

		if (maj_stat != GSS_S_COMPLETE || qop_state != qop) {
			gss_release_buffer(&min_stat, &databuf);
			gss_log_status("gss_verify_mic", maj_stat, min_stat);
			return (FALSE);
		}
	} else if (svc == RPCSEC_GSS_SVC_PRIVACY) {
		/* Decode databody_priv. */
		if (!xdr_rpc_gss_decode(xdrs, &wrapbuf)) {
			__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
				"%s() xdr_rpc_gss_decode databody_priv failed",
				__func__);
			return (FALSE);
		}
		/* Decrypt databody. */
		maj_stat =
		    gss_unwrap(&min_stat, ctx, &wrapbuf, &databuf, &conf_state,
			       &qop_state);

		gss_release_buffer(&min_stat, &wrapbuf);

		/* Verify encryption and QOP. */
		if (maj_stat != GSS_S_COMPLETE || qop_state != qop
		    || conf_state != TRUE) {
			gss_release_buffer(&min_stat, &databuf);
			gss_log_status("gss_unwrap", maj_stat, min_stat);
			return (FALSE);
		}
	}
	/* Decode rpc_gss_data_t (sequence number + arguments). */
	xdrmem_create(&tmpxdrs, databuf.value, databuf.length, XDR_DECODE);
	xdr_stat = (XDR_GETUINT32(&tmpxdrs, &seq_num)
		    && (*xdr_func) (&tmpxdrs, xdr_ptr));
	XDR_DESTROY(&tmpxdrs);
	gss_release_buffer(&min_stat, &databuf);

	/* Verify sequence number. */
	if (xdr_stat == TRUE && seq_num != seq) {
		__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
			"%s() wrong sequence number in databody",
			__func__);
		return (FALSE);
	}
	return (xdr_stat);
}

#ifdef DEBUG
#include <ctype.h>

void
gss_log_status(char *m, OM_uint32 maj_stat, OM_uint32 min_stat)
{
	OM_uint32 min;
	gss_buffer_desc msg;
	int msg_ctx = 0;

	__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS, "rpcsec_gss: %s: ", m);

	gss_display_status(&min, maj_stat, GSS_C_GSS_CODE, GSS_C_NULL_OID,
			   &msg_ctx, &msg);
	__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS, "%s - ", (char *)msg.value);
	gss_release_buffer(&min, &msg);

	gss_display_status(&min, min_stat, GSS_C_MECH_CODE, GSS_C_NULL_OID,
			   &msg_ctx, &msg);
	__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS, "%s\n", (char *)msg.value);
	gss_release_buffer(&min, &msg);
}

#define DUMP_BYTES_PER_GROUP (4)
#define DUMP_GROUPS_PER_LINE (4)
#define DUMP_BYTES_PER_LINE (DUMP_BYTES_PER_GROUP * DUMP_GROUPS_PER_LINE)

void
gss_log_hexdump(const u_char *buf, int len, int offset)
{
	char *buffer;
	uint8_t *datum = buf;
	int sized = len - offset;
	int buffered = (((sized / DUMP_BYTES_PER_LINE) + 1 /*partial line*/)
			* (12 /* heading */
			   + (((DUMP_BYTES_PER_GROUP * 2 /*%02X*/) + 1 /*' '*/)
			      * DUMP_GROUPS_PER_LINE)))
			+ 1 /*'\0'*/;
	int i = 0;
	int m = 0;

	if (sized == 0) {
		__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
			"%s()\n");
		return;
	}
	buffer = (char *)mem_alloc(buffered);

	while (sized > i) {
		int j = sized - i;
		int k = j < DUMP_BYTES_PER_LINE ? j : DUMP_BYTES_PER_LINE;
		int l = 0;
		int r = sprintf(&buffer[m], "\n%10d:", i);	/* heading */

		if (r < 0)
			goto quit;
		m += r;

		for (; l < k; l++) {
			if (l % DUMP_BYTES_PER_GROUP == 0)
				buffer[m++] = ' ';

			r = sprintf(&buffer[m], "%02X", datum[i++]);
			if (r < 0)
				goto quit;
			m += r;
		}
	}
quit:
	buffer[m] = '\0';	/* in case of error */
	__warnx(TIRPC_DEBUG_FLAG_RPCSEC_GSS,
		"%s() %s\n",
		buffer);
	mem_free(buffer, buffered);
}

#else

void
gss_log_status(char *m, OM_uint32 maj_stat, OM_uint32 min_stat)
{
}

void
gss_log_hexdump(const u_char *buf, int len, int offset)
{
}

#endif

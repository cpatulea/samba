/*
   Unix SMB/CIFS implementation.

   main select loop and event handling - glib implementation

   Based on tevent_epoll.c, which are:
	   Copyright (C) Andrew Tridgell	2003-2005
	   Copyright (C) Stefan Metzmacher	2005-2009
   Glib-specific code is:
	   Copyright (C) Catalin Patulea	2012

     ** NOTE! The following LGPL license applies to the tevent
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "tevent.h"
#include "tevent_internal.h"
#include <glib.h>
#include <sys/time.h>

/*
 * This backend layers tevent on top of glib's main event loop. This lets
 * glib applications embed clients of tevent (e.g. smbclient-raw) and perform
 * asynchronous operations within a single thread.
 *
 * fds map to a (GIOChannel, GSource) pair, created with g_io_channel_unix_new()
 * and g_io_create_watch(), respectively. For a given fd, all requested flags
 * are handled by a single IO watch. Modification of the flags after add_fd
 * (set_flags) is handled by destroying and re-creating the IO watch with the
 * new flags.
 *
 * Timers map to a GSource created using g_timeout_source_new(). tevent timers
 * are one-shot, while glib timeouts are periodic, so the glib callback always
 * destroys the timeout source before returning. Freeing the tevent timer by the
 * client, from within the handler, is denied to prevent a double-free upon
 * return to the glib callback.
 *
 * The fd and timer implementations delegate to the tevent_common_* helpers to
 * manage the DLISTs of fds/timers in the tevent_context. This is not strictly
 * necessary because glib internally manages its list of sources, but may help
 * for debugging or if the internal structures of tevent_{context,fd,timer}
 * changes.
 *
 * Immediates and signals are handled by tevent_common_*. They are checked just
 * before entering the glib mainloop, similar to how epoll handles them before
 * entering epoll_wait. Signals in fact use a pipe and therefore depend on
 * add_fd.
 *
 * Sources are always attached to a specific GMainContext created along with the
 * tevent context, so in theory it should be possible to manage this tevent
 * context from a different thread than the one that runs the mainloop. However,
 * that is not all there is to thread-safety to you should treat this
 * implementation as *thread-unsafe*.
 */

/*
 * event context implementation
 */
struct glib_event_context {
	/* a pointer back to the generic event_context */
	struct tevent_context *ev;

	GMainContext *ctx;
};

static int glib_event_context_init(struct tevent_context *ev);
static int glib_ctx_destructor(struct glib_event_context *glib_ev);

/* create a glib_event_context structure */
static int glib_event_context_init(struct tevent_context *ev)
{
	int ret;
	struct glib_event_context *glib_ev;

	glib_ev = talloc(ev, struct glib_event_context);
	if (!glib_ev) return -1;

	glib_ev->ev = ev;

	glib_ev->ctx = g_main_context_new();
	if (!glib_ev->ctx) {
		tevent_debug(ev, TEVENT_DEBUG_FATAL,
			     "Failed to create GMainContext.\n");
		return -1;
	}

	talloc_set_destructor(glib_ev, glib_ctx_destructor);

	ev->additional_data = glib_ev;
	return 0;
}

/* free the glib maincontext */
static int glib_ctx_destructor(struct glib_event_context *glib_ev)
{
	g_main_context_unref(glib_ev->ctx);
	glib_ev->ctx = NULL;
	return 0;
}

/*
 * utility
 */

/* called when a glib call fails */
static void glib_panic(struct glib_event_context *glib_ev, const char *reason)
{
	tevent_debug(glib_ev->ev, TEVENT_DEBUG_FATAL,
		 "%s - calling abort()\n", reason);
	abort();
}

/* map from TEVENT_FD_* to G_IO_* */
static GIOCondition glib_map_flags(uint16_t flags)
{
	GIOCondition ret = 0;
	if (flags & TEVENT_FD_READ) ret |= (G_IO_IN | G_IO_ERR | G_IO_HUP);
	if (flags & TEVENT_FD_WRITE) ret |= (G_IO_OUT | G_IO_ERR | G_IO_HUP);
	return ret;
}

/*
 * add_fd implementation
 */
struct glib_fd {
	struct tevent_context *event_ctx;
	GIOChannel *chan;
	GSource *watch;
};

static struct tevent_fd *glib_event_add_fd(struct tevent_context *ev,
					   TALLOC_CTX *mem_ctx,
					   int fd, uint16_t flags,
					   tevent_fd_handler_t handler,
					   void *private_data,
					   const char *handler_name,
					   const char *location);
static void glib_event_set_fd_flags(struct tevent_fd *fde, uint16_t flags);
static gboolean glib_event_fd_func(GIOChannel *source, GIOCondition condition,
				   gpointer data);
static int glib_event_fd_destructor(struct tevent_fd *fde);
static int glib_glib_fd_destructor(struct glib_fd *gfd);

/*
  add a fd based event
  return NULL on failure (memory allocation error)
*/
static struct tevent_fd *glib_event_add_fd(struct tevent_context *ev,
					   TALLOC_CTX *mem_ctx,
					   int fd, uint16_t flags,
					   tevent_fd_handler_t handler,
					   void *private_data,
					   const char *handler_name,
					   const char *location)
{
	uint16_t initial_flags;
	struct tevent_fd *fde;
	struct glib_fd *gfd;

	/* for the first set_fd_flags to behave correctly */
	initial_flags = 0;

	fde = tevent_common_add_fd(ev, mem_ctx, fd, initial_flags, handler, 
				   private_data, handler_name, location);
	if (!fde) return NULL;

	/* only for debugging at the moment */
	talloc_set_destructor(fde, glib_event_fd_destructor);

	/* XXX: is parenting gfd to fde the right thing to do here? */
	gfd = talloc(fde, struct glib_fd);
	if (!gfd) goto fail;

	gfd->event_ctx = ev;
	gfd->chan = NULL;
	gfd->watch = NULL;

	talloc_set_destructor(gfd, glib_glib_fd_destructor);

	fde->additional_data = gfd;

	gfd->chan = g_io_channel_unix_new(fd);
	if (!gfd->chan) goto fail;

	tevent_debug(fde->event_ctx, TEVENT_DEBUG_TRACE,
		     "Add fd %d fde %p gfd %p (g_io_channel %p#%d)\n",
		     fde->fd, fde, gfd, gfd->chan, gfd->chan->ref_count);

	/* create first watch */
	glib_event_set_fd_flags(fde, flags);

	return fde;

fail:
	talloc_free(fde);
	return NULL;
}

static void glib_event_set_fd_flags(struct tevent_fd *fde, uint16_t flags)
{
	struct glib_fd *gfd =
		talloc_get_type(fde->additional_data, struct glib_fd);
	struct tevent_context *ev =
		talloc_get_type(fde->event_ctx, struct tevent_context);
	struct glib_event_context *glib_ev =
		talloc_get_type(ev->additional_data, struct glib_event_context);
	GIOCondition cond;
	guint source_id;

	if (fde->flags == flags) return;

	if (gfd->watch)	{
		g_source_unref(gfd->watch);
		gfd->watch = NULL;
	}

	cond = glib_map_flags(flags);
	gfd->watch = g_io_create_watch(gfd->chan, cond);
	if (!gfd->watch) {
		/* XXX: handle this more gracefully when called from add_fd */
		glib_panic(glib_ev, "g_io_create_watch failed");
		/* notreached */ return;
	}

	g_source_set_callback(gfd->watch, (GSourceFunc)glib_event_fd_func, fde,
			      NULL);

	source_id = g_source_attach(gfd->watch, glib_ev->ctx);

	fde->flags = flags;

	tevent_debug(fde->event_ctx, TEVENT_DEBUG_TRACE,
		     "Set fd %d flags=0x%02x "
		     "(g_io_watch %p#%d id=%u cond=0x%02x)\n",
		     fde->fd, fde->flags,
		     gfd->watch, gfd->watch->ref_count, source_id, cond);
}

static gboolean glib_event_fd_func(GIOChannel *source, GIOCondition condition,
				   gpointer data)
{
	struct tevent_fd *fde = talloc_get_type(data, struct tevent_fd);
	struct glib_fd *gfd =
		talloc_get_type(fde->additional_data, struct glib_fd);
	uint16_t flags;

	tevent_debug(fde->event_ctx, TEVENT_DEBUG_TRACE,
		     "Run fd %d cond=0x%02x\n",
		     fde->fd, condition);

	flags = 0;
	if (condition & (G_IO_HUP | G_IO_ERR)) {
		if (!(fde->flags & TEVENT_FD_READ)) {
			TEVENT_FD_NOT_WRITEABLE(fde);
			return FALSE;
		}
		flags |= TEVENT_FD_READ;
	}

	if (condition & G_IO_IN) flags |= TEVENT_FD_READ;
	if (condition & G_IO_OUT) flags |= TEVENT_FD_WRITE;

	fde->handler(fde->event_ctx, fde, flags, fde->private_data);
	/* handler may have freed gfd and fde */
	fde = NULL;
	gfd = NULL;

	return TRUE;
}

static int glib_event_fd_destructor(struct tevent_fd *fde)
{
	struct glib_fd *gfd =
		talloc_get_type(fde->additional_data, struct glib_fd);

	tevent_debug(fde->event_ctx, TEVENT_DEBUG_TRACE,
		     "Destruct fd %d fde %p gfd %p\n",
		     fde->fd, fde, gfd);
	return tevent_common_fd_destructor(fde);
}

static int glib_glib_fd_destructor(struct glib_fd *gfd)
{
	g_source_destroy(gfd->watch);
	g_source_unref(gfd->watch);
	g_io_channel_unref(gfd->chan);

	tevent_debug(gfd->event_ctx, TEVENT_DEBUG_TRACE,
		     "Destruct gfd %p watch %p#%d chan %p#%d\n",
		     gfd,
		     gfd->watch, gfd->watch->ref_count,
		     gfd->chan, gfd->chan->ref_count);

	gfd->watch = NULL;
	gfd->chan = NULL;
	return 0;
}

/*
 * add_timer implementation
 */
static struct tevent_timer *glib_event_add_timer(struct tevent_context *ev,
						 TALLOC_CTX *mem_ctx,
						 struct timeval next_event,
						 tevent_timer_handler_t handler,
						 void *private_data,
						 const char *handler_name,
						 const char *location);
static gboolean glib_event_timer_func(gpointer data);
static int glib_event_timer_destructor(struct tevent_timer *te);
static int glib_event_timer_deny_destruct(struct tevent_timer *te);

/* add a timed event */
static struct tevent_timer *glib_event_add_timer(struct tevent_context *ev,
						 TALLOC_CTX *mem_ctx,
						 struct timeval next_event,
						 tevent_timer_handler_t handler,
						 void *private_data,
						 const char *handler_name,
						 const char *location)
{
	struct glib_event_context *glib_ev = talloc_get_type(
		ev->additional_data, struct glib_event_context);
	struct tevent_timer *te;
	guint delta_ms;
	GSource *timeout_source;
	guint source_id;

	te = tevent_common_add_timer(ev, mem_ctx, next_event, handler,
				     private_data, handler_name, location);
	if (!te) return NULL;

	if (tevent_timeval_is_zero(&te->next_event)) {
		delta_ms = 0;
	} else {
		GTimeVal now;

		g_get_current_time(&now);
		gint64 delta_us = next_event.tv_sec * 1000000LL +
				  next_event.tv_usec -
				  now.tv_sec * 1000000LL -
				  now.tv_usec;

		/* round up like tevent_{epoll,poll,standard} */
		delta_ms = (delta_us + 999) / 1000;
	}

	/* create the source manually so we can attach to a specific maincontext
	 */
	timeout_source = g_timeout_source_new(delta_ms);
	if (!timeout_source) {
		talloc_free(te);
		return NULL;
	}

	g_source_set_callback(timeout_source, glib_event_timer_func, te, NULL);
	source_id = g_source_attach(timeout_source, glib_ev->ctx);

	te->additional_data	= timeout_source;

	/* pass reference to te, i.e.,
	g_source_ref(te->additional_data);
	g_source_unref(timeout_source);
	*/
	timeout_source = NULL;

	talloc_set_destructor(te, glib_event_timer_destructor);

	tevent_debug(ev, TEVENT_DEBUG_TRACE,
		     "Added timer (g_timeout_source %p#%d delta_ms=%d id=%u) "
		     "\"%s\": %p\n",
		     te->additional_data,
		     ((GSource *)te->additional_data)->ref_count,
		     delta_ms, source_id, handler_name, te);
	return te;
}

static gboolean glib_event_timer_func(gpointer data)
{
	struct tevent_timer *te = talloc_get_type(data, struct tevent_timer);
	GTimeVal g_now;
	struct timeval now;

	tevent_debug(te->event_ctx, TEVENT_DEBUG_TRACE,
		     "Run timer %p timeout_source %p#%d\n",
		     te, te->additional_data,
		     ((GSource *)te->additional_data)->ref_count);

	g_get_current_time(&g_now);
	now.tv_sec = g_now.tv_sec;
	now.tv_usec = g_now.tv_usec;

	talloc_set_destructor(te, glib_event_timer_deny_destruct);
	te->handler(te->event_ctx, te, now, te->private_data);

	talloc_set_destructor(te, glib_event_timer_destructor);
	talloc_free(te);

	/* should not matter what we return here - source should have already
	 * been destroyed in glib_event_timer_destructor */
	return FALSE;
}

static int glib_event_timer_destructor(struct tevent_timer *te)
{
	GSource *timeout_source = (GSource *)te->additional_data;
	g_source_destroy(timeout_source);
	g_source_unref(timeout_source);
	tevent_debug(te->event_ctx, TEVENT_DEBUG_TRACE,
		     "Destruct timer %p source %p#%d\n",
		     te, timeout_source, timeout_source->ref_count);
	timeout_source = te->additional_data = NULL;
	return tevent_common_timed_destructor(te);
}

static int glib_event_timer_deny_destruct(struct tevent_timer *te)
{
	return -1;
}

/* do a single event loop using the events defined in ev */
static int glib_event_loop_once(struct tevent_context *ev, const char *location)
{
	struct glib_event_context *glib_ev =
		talloc_get_type(ev->additional_data, struct glib_event_context);

	if (ev->signal_events &&
	    tevent_common_check_signal(ev)) {
		return 0;
	}

	if (ev->immediate_events &&
	    tevent_common_loop_immediate(ev)) {
		return 0;
	}

	tevent_debug(ev, TEVENT_DEBUG_TRACE,
		     "Loop once (g_main_context_iteration) from \"%s\"\n",
		     location);
	(void)g_main_context_iteration(glib_ev->ctx, TRUE);
	return 0;
}

static const struct tevent_ops glib_event_ops = {
	.context_init		= glib_event_context_init,
	.add_fd			= glib_event_add_fd,
	.set_fd_close_fn	= tevent_common_fd_set_close_fn,
	.get_fd_flags		= tevent_common_fd_get_flags,
	.set_fd_flags		= glib_event_set_fd_flags,
	.add_timer		= glib_event_add_timer,
	.schedule_immediate	= tevent_common_schedule_immediate,
	.add_signal		= tevent_common_add_signal,
	.loop_once		= glib_event_loop_once,
	.loop_wait		= tevent_common_loop_wait,
};

_PRIVATE_ bool tevent_glib_init(void)
{
	return tevent_register_backend("glib", &glib_event_ops);
}

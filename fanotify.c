/*
| fanotify.c from Lsyncd - Live (Mirror) Syncing Demon
|
| License: GPLv2 (see COPYING) or any later version
|
| Authors: Oleg Stepanischev <olegxx@gmail.com>
|
| -----------------------------------------------------------------------
|
| Event interface for Lsyncd to Linux´ fanotify.
*/

#include "lsyncd.h"

#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/fanotify.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <math.h>
#include <time.h>
#include <unistd.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#define FANOTIFY_BUFSIZE 256*1024

/* work around kernels which do not have this fix yet:
* http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=1e2ee49f7
* O_LARGEFILE is usually 0, so hardcode it here
*/
#define KERNEL_O_LARGEFILE 00100000

int fanotify_fd;
void *readbuf = NULL;
static pid_t self_pid;

static const char * MODIFY = "Modify";

/*
| Adds an fanotify watch
|
| param dir         (Lua stack) path to directory
| return            nil
*/
static int
l_addwatch(lua_State *L)
{
	const char *path = luaL_checkstring(L, 1);

	int res = fanotify_mark(fanotify_fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_CLOSE_WRITE, AT_FDCWD, path);
	if (res < 0) {
		printlogf(
			L,
			"Error",
			"Failed to add watch for %s: (%d) %s",
			path, errno, strerror(errno)
		);
		exit(-1);
	}

	return 0;
}

/*
* Removes an fanotify watch.
*
| param dir         (Lua stack) path to directory
| return            nil
*/
static int
l_rmwatch(lua_State *L)
{
	const char *path = luaL_checkstring(L, 1);

	int res = fanotify_mark(fanotify_fd, FAN_MARK_REMOVE | FAN_MARK_MOUNT, FAN_CLOSE_WRITE, AT_FDCWD, path);
	if (res < 0) {
		printlogf(
			L,
			"Error",
			"Failed to remove watch for %s: (%d) %s",
			path, errno, strerror(errno)
		);
		exit(-1);
	}

	lua_pushinteger(L, 0);
}

/*
| Handles an fanotify event.
*/
static void
handle_event(
	lua_State *L,
	struct fanotify_event_metadata *data
)
{
	static char pathname[PATH_MAX];
	static char printbuf[100];
	int len;

	if (data && (FAN_Q_OVERFLOW & data->mask))
	{
		// and overflow happened, tells the runner
		load_runner_func(L, "overflow");

		if (lua_pcall(L, 0, 0, -2))
		{
			exit(-1);
		}

		lua_pop(L, 1);
		hup = 1;
		return;
	}

	snprintf(printbuf, sizeof(printbuf), "/proc/self/fd/%i", data->fd);
	len = readlink(printbuf, pathname, sizeof(pathname));

	if (len <= 0) {
		return;
	}

	pathname[len] = '\0';

	// hands the event over to the runner
	load_runner_func(L, "fanotifyEvent");

	lua_pushstring(L, MODIFY);
	lua_pushboolean(L, (data->mask & FAN_ONDIR) != 0);
	l_now(L);
	lua_pushstring(L, pathname);

	if (lua_pcall(L, 4, 0, -6))
	{
		exit(-1);
	}

	lua_pop(L, 1);
}

static void
fanotify_ready(
	lua_State *L,
	struct observance *obs
)
{
	int res;
	struct fanotify_event_metadata *data;

	// sanity check
	if (obs->fd != fanotify_fd)
	{
		logstring(
			"Error",
			"internal failure, fanotify_fd != ob->fd"
		);
		exit(-1);
	}

	while (true) {
		res = read(fanotify_fd, readbuf, FANOTIFY_BUFSIZE);

		if (res == 0) {
			break;
		}

		if (res < 0) {
			if (errno == EAGAIN) {
				break;
			}

			if (errno == EINTR)
				continue;

			printlogf(
				L,
				"Error",
				"Fanotify read error ( %d : %s )",
				errno, strerror(errno)
			);
			exit(-1);
		}

		data = (struct fanotify_event_metadata *) readbuf;
		while (FAN_EVENT_OK(data, res)) {
			// exclude self pid
			if (data->pid != self_pid) {
				handle_event(L, data);
			}

			close(data->fd);
			data = FAN_EVENT_NEXT(data, res);
		}
	}
}

/*
| Lsyncd's core's fanotify functions.
*/
static const luaL_Reg lfanotfylib[] =
{
	{ "addwatch",   l_addwatch },
	{ "rmwatch",    l_rmwatch },
	{ NULL, NULL }
};

/*
| Registers the fanotify functions.
*/
extern void
register_fanotify(lua_State *L)
{
	lua_compat_register(L, LSYNCD_FANOTIFYLIBNAME, lfanotfylib);
}

/*
| Cleans up the fanotify handling.
*/
static void
fanotify_tidy(struct observance *obs)
{
	if (obs->fd != fanotify_fd)
	{
		logstring(
			"Error",
			"internal failure: fanotify_fd != ob->fd"
		);

		exit(-1);
	}

	close(fanotify_fd);

	free(readbuf);

	readbuf = NULL;
}
/*
| Initalizes fanotify handling
*/
extern void
open_fanotify(lua_State *L)
{
	int err;

	if (readbuf)
	{
		logstring(
			"Error",
			"internal failure, fanotify readbuf != NULL in open_fanotify()"
		)
			exit(-1);
	}

	readbuf = NULL;
	err = posix_memalign(&readbuf, 4096, FANOTIFY_BUFSIZE);
	if (err != 0 || readbuf == NULL) {
		logstring(
			"Error",
			"Cannot allocate buffer"
		)
		exit(-1);
	}

	self_pid = getpid();
	fanotify_fd = fanotify_init(FAN_NONBLOCK | FAN_CLOEXEC, KERNEL_O_LARGEFILE);

	if (fanotify_fd < 0)
	{
		printlogf(
			L,
			"Error",
			"Cannot access fanotify monitor! ( %d : %s )",
			errno, strerror(errno)
		);

		err = errno;
		if (err == EPERM) {
			logstring(
				"Error",
				"You need to run this program as root"
			)
		}

		exit(-1);
	}

	printlogf(
		L, "Fanotify",
		"fanotify fd = %d, pid = %d",
		fanotify_fd, self_pid
	);

	close_exec_fd(fanotify_fd);
	non_block_fd(fanotify_fd);

	observe_fd(
		fanotify_fd,
		fanotify_ready,
		NULL,
		fanotify_tidy,
		NULL
	);
}


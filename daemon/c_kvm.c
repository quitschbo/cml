/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2024 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/*
 * @file c_kvm.c
 *
 * This module integrates the main funtionlity to wire up kvm related configuration
 * if COMPARTMENT_TYPE_KVM is selected for a container
 */

#define _GNU_SOURCE

#define MOD_NAME "c_kvm"

#include "common/macro.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/proc.h"
#include "container.h"

#include <fcntl.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BUSYBOX_PATH "/bin/busybox"
#define LKVM_PATH "/usr/bin/lkvm"
#define KVM_CONTAINER_LOGFILE "/var/log/kvm.log"

typedef struct c_kvm {
	compartment_t *compartment;
	const container_t *container;
	char *tty_path;
} c_kvm_t;

static void *
c_kvm_new(compartment_t *compartment)
{
	ASSERT(compartment);

	c_kvm_t *kvm = mem_new0(c_kvm_t, 1);
	kvm->compartment = compartment;
	kvm->container = compartment_get_extension_data(compartment);

	kvm->tty_path = NULL;

	return kvm;
}

static void
c_kvm_free(void *kvmp)
{
	c_kvm_t *kvm = kvmp;
	ASSERT(kvm);
	mem_free0(kvm);
}

static int
c_kvm_start_pre_clone(void *kvmp)
{
	c_kvm_t *kvm = kvmp;
	ASSERT(kvm);

	const char *kvm_home = compartment_get_debug_log_dir(kvm->compartment);
	char *kvm_log = mem_printf("%s/kvm-log", kvm_home);
	char *kvm_root = mem_printf("/tmp/%s", uuid_string(compartment_get_uuid(kvm->compartment)));

	char **init_env = mem_new0(char *, 1);
	init_env[0] = mem_printf("HOME=%s", LKVM_PATH);

	compartment_init_env_prepend(kvm->compartment, init_env, 1);

	mem_free0(init_env[0]);
	mem_free0(init_env);

	char **compartment_init_argv = compartment_get_init_argv(kvm->compartment);

	char *kernel_params = NULL;
	for (char **arg = compartment_init_argv; *arg; arg++) {
		if (!kernel_params)
			kernel_params = mem_printf("console=/dev/ttyS1 init=%s --", *arg);
		else
			kernel_params = mem_printf("%s %s", kernel_params, *arg);

		DEBUG("\t%s", kernel_params);
	}

	const char *const argv[] = { "/usr/bin/lkvm",
				     "run",
				     "-d",
				     kvm_root,
				     "--name",
				     uuid_string(compartment_get_uuid(kvm->compartment)),
				     "--kernel",
				     "/boot/bzImage-gyroidos",
				     "--vsock",
				     "3",
				     "--tty",
				     "1",
				     "--params",
				     kernel_params,
				     NULL };

	DEBUG("setting lkvm specific argv!");
	// overwrite compartments init_argv with kvm specific prepends
	compartment_set_init_argv(kvm->compartment, argv, 15);
	mem_free(kernel_params);

	if (!compartment_has_userns(kvm->compartment))
		return 0;

	// here we have the mapped ids in case of userns is enabled
	int uid = container_get_uid(kvm->container);
	if (chown(kvm_home, uid, uid) < 0) {
		ERROR_ERRNO("Could not chown kvm_home dir '%s' to (%d:%d)", kvm_home, uid, uid);
		goto error;
	}

	if (dir_mkdir_p(kvm_log, 0755) < 0) {
		ERROR_ERRNO("Could not create kvm_log dir '%s' to (%d:%d)", kvm_log, uid, uid);
		goto error;
	}

	if (chown(kvm_log, uid, uid) < 0) {
		ERROR_ERRNO("Could not chown kvm_log file '%s' to (%d:%d)", kvm_log, uid, uid);
		goto error;
	}

	if (dir_mkdir_p(kvm_root, 0755) < 0) {
		ERROR_ERRNO("Could not create kvm_root dir '%s' to (%d:%d)", kvm_root, uid, uid);
		goto error;
	}

	if (chown(kvm_root, uid, uid) < 0) {
		ERROR_ERRNO("Could not chown kvm_root dir '%s' to (%d:%d)", kvm_root, uid, uid);
		goto error;
	}

	mem_free(kvm_root);
	mem_free0(kvm_log);

	INFO("pre_clone end");
	return 0;

error:
	mem_free(kvm_root);
	mem_free0(kvm_log);
	return -COMPARTMENT_ERROR;
}

#if 0 
UNUSED static int
c_kvm_start_pre_exec_child(void *kvmp)
{
	c_kvm_t *kvm = kvmp;
	ASSERT(kvm);

	if (!compartment_has_userns(kvm->compartment))
		return 0;

	// here we have the mapped ids in case of userns is enabled
	char *kvm_dev =
		mem_printf("/tmp/%s/dev", uuid_string(compartment_get_uuid(kvm->compartment)));

	if (mount(kvm_dev, "/dev", NULL, MS_BIND, NULL) < 0) {
		ERROR_ERRNO("Could not bind mount mapped /dev");
		goto error;
	}

	if (mount("devpts", "/dev/pts", "devpts", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not mount /dev/pts");
		goto error;
	}

	mem_free0(kvm_dev);
	return 0;

error:
	mem_free0(kvm_dev);
	return -COMPARTMENT_ERROR;
}
#endif

static void
c_kvm_log_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	c_kvm_t *kvm = data;
	ASSERT(kvm);

	char *buf = mem_alloc0(1024);

	if ((events & EVENT_IO_READ)) {
		int read_bytes = fd_read(fd, buf, 1024);
		if (-1 == file_write_append(KVM_CONTAINER_LOGFILE, buf, read_bytes))
			WARN("Could not write to logfile %s", KVM_CONTAINER_LOGFILE);
	}

	if (events & EVENT_IO_EXCEPT) {
		event_remove_io(io);
		event_io_free(io);
		close(fd);
	}
}

static void
c_kvm_pts_inotify_cb(const char *path, UNUSED uint32_t mask, event_inotify_t *inotify, void *data)
{
	c_kvm_t *kvm = data;
	ASSERT(kvm);

	DEBUG("Pseudo terminal created %s, take it as our tty to the guest VM", path);
	if (kvm->tty_path)
		mem_free0(kvm->tty_path);
	kvm->tty_path = mem_strdup(path);

	event_remove_inotify(inotify);
	event_inotify_free(inotify);

	int fd = open(kvm->tty_path, O_RDONLY | O_NONBLOCK);

	IF_TRUE_RETURN(fd < 0);

	event_io_t *io = event_io_new(fd, EVENT_IO_READ | EVENT_IO_EXCEPT, c_kvm_log_cb, kvm);
	event_add_io(io);
}

static int
c_kvm_start_pre_exec_child(void *kvmp)
{
	c_kvm_t *kvm = kvmp;
	ASSERT(kvm);

	event_inotify_t *inotify =
		event_inotify_new("/dev/pts/", IN_CREATE, c_kvm_pts_inotify_cb, kvm);
	event_add_inotify(inotify);

	return 0;
}

static compartment_module_t c_kvm_module = {
	.name = MOD_NAME,
	.compartment_new = c_kvm_new,
	.compartment_free = c_kvm_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = c_kvm_start_pre_clone,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child = c_kvm_start_pre_exec_child,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
c_kvm_init(void)
{
	// register this module in container.c
	compartment_register_module(&c_kvm_module);
}

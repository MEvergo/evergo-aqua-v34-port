// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../kselftest.h"
#include "clone3_selftests.h"

#define CAP_WORD(cap) ((cap) / 32)
#define CAP_MASK(cap) (1U << ((cap) % 32))
#define CHECKPOINT_RESTORE_WORD CAP_WORD(CAP_CHECKPOINT_RESTORE)
#define CHECKPOINT_RESTORE_MASK CAP_MASK(CAP_CHECKPOINT_RESTORE)

#define TEST_SETUP_SKIP 77
#define TEST_SETUP_FAIL 78
#define TEST_DENIED_PASS 1
#define TEST_ALLOWED_PASS 2
#define TEST_PID_CANDIDATES 128

static void test_clone3_supported(void)
{
	struct clone_args args = {};
	pid_t pid;

	if (__NR_clone3 < 0)
		ksft_exit_skip("clone3() syscall is not supported\n");

	/* An invalid exit signal must be rejected by a supported clone3(). */
	args.exit_signal = -1;
	pid = sys_clone3(&args, sizeof(args));
	if (pid == 0)
		_exit(EXIT_FAILURE);
	if (pid > 0) {
		waitpid(pid, NULL, 0);
		ksft_exit_fail_msg("clone3() accepted an invalid exit signal\n");
	}
	if (errno == ENOSYS)
		ksft_exit_skip("clone3() syscall is not supported\n");
}

static int capget(struct __user_cap_data_struct *caps)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};

	return syscall(SYS_capget, &header, caps);
}

static int capset_checkpoint_restore(bool effective)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3] = {};

	caps[CHECKPOINT_RESTORE_WORD].permitted = CHECKPOINT_RESTORE_MASK;
	if (effective)
		caps[CHECKPOINT_RESTORE_WORD].effective =
			CHECKPOINT_RESTORE_MASK;

	return syscall(SYS_capset, &header, caps);
}

static bool has_cap(const struct __user_cap_data_struct *caps, int cap,
		    bool effective, bool permitted)
{
	unsigned int word = CAP_WORD(cap);
	unsigned int mask = CAP_MASK(cap);

	return (effective && (caps[word].effective & mask)) ||
	       (permitted && (caps[word].permitted & mask));
}

static bool has_only_checkpoint_restore(bool effective)
{
	struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3] = {};
	unsigned int i;

	if (capget(caps) < 0)
		return false;

	for (i = 0; i < _LINUX_CAPABILITY_U32S_3; i++) {
		unsigned int permitted = i == CHECKPOINT_RESTORE_WORD ?
					 CHECKPOINT_RESTORE_MASK : 0;
		unsigned int effective_caps = effective ? permitted : 0;

		if (caps[i].permitted != permitted ||
		    caps[i].effective != effective_caps || caps[i].inheritable)
			return false;
	}

	return true;
}

static int drop_to_unprivileged_user(void)
{
	struct __user_cap_data_struct caps[_LINUX_CAPABILITY_U32S_3] = {};

	if (geteuid() != 0)
		return TEST_SETUP_SKIP;
	if (capget(caps) < 0)
		return TEST_SETUP_FAIL;
	if (!has_cap(caps, CAP_CHECKPOINT_RESTORE, false, true) ||
	    !has_cap(caps, CAP_SETUID, true, false) ||
	    !has_cap(caps, CAP_SETGID, true, false))
		return TEST_SETUP_SKIP;

	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0 ||
	    setgroups(0, NULL) < 0 ||
	    setresgid(65534, 65534, 65534) < 0 ||
	    setresuid(65534, 65534, 65534) < 0)
		return TEST_SETUP_SKIP;

	if (getuid() == 0 || geteuid() == 0 || getgid() == 0 || getegid() == 0)
		return TEST_SETUP_FAIL;

	if (capget(caps) < 0 ||
	    !has_cap(caps, CAP_CHECKPOINT_RESTORE, false, true))
		return TEST_SETUP_FAIL;

	return 0;
}

static int read_pid_max(pid_t *pid_max)
{
	FILE *file;
	int value;

	file = fopen("/proc/sys/kernel/pid_max", "r");
	if (!file)
		return -1;
	if (fscanf(file, "%d", &value) != 1) {
		fclose(file);
		return -1;
	}
	fclose(file);
	if (value <= 2)
		return -1;

	*pid_max = value;
	return 0;
}

/* Return 0 if a child with the requested PID was created and reaped. */
static int clone3_with_requested_pid(pid_t requested_pid)
{
	struct clone_args args = {
		.exit_signal = SIGCHLD,
		.set_tid = ptr_to_u64(&requested_pid),
		.set_tid_size = 1,
	};
	pid_t pid;
	int status;

	pid = sys_clone3(&args, sizeof(args));
	if (pid < 0)
		return -errno;
	if (pid == 0)
		_exit(getpid() == requested_pid ? EXIT_SUCCESS : EXIT_FAILURE);
	if (pid != requested_pid) {
		while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
			;
		return -ECHILD;
	}

	while (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR)
			continue;
		return -errno;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
		return -ECHILD;

	return 0;
}

static int try_requested_pid(pid_t pid_max, int expected_result)
{
	int i;

	for (i = 0; i < TEST_PID_CANDIDATES; i++) {
		pid_t requested_pid = pid_max - 1 - i;
		int result;

		if (requested_pid <= 1)
			break;
		result = clone3_with_requested_pid(requested_pid);
		if (result == -EEXIST)
			continue;
		return result == expected_result ? 0 : -1;
	}

	return -1;
}

static int run_capability_tests(void)
{
	pid_t pid_max;
	int result = 0;
	int setup;

	setup = drop_to_unprivileged_user();
	if (setup)
		return setup;
	if (read_pid_max(&pid_max) < 0)
		return TEST_SETUP_SKIP;

	/* Keep CAP_CHECKPOINT_RESTORE permitted, but not effective, for EPERM. */
	if (capset_checkpoint_restore(false) < 0 ||
	    !has_only_checkpoint_restore(false))
		return TEST_SETUP_FAIL;

	if (try_requested_pid(pid_max, -EPERM) == 0)
		result |= TEST_DENIED_PASS;

	/* Restore only CAP_CHECKPOINT_RESTORE to the effective set. */
	if (capset_checkpoint_restore(true) == 0 &&
	    has_only_checkpoint_restore(true) &&
	    try_requested_pid(pid_max, 0) == 0)
		result |= TEST_ALLOWED_PASS;

	return result;
}

int main(void)
{
	pid_t pid;
	int status;
	int result;

	ksft_print_header();
	ksft_set_plan(2);

	test_clone3_supported();

	pid = fork();
	if (pid < 0) {
		ksft_test_result_fail("fork() failed: %s\n", strerror(errno));
		ksft_test_result_fail("fork() failed: %s\n", strerror(errno));
		return ksft_get_fail_cnt() ? ksft_exit_fail() : ksft_exit_pass();
	}
	if (pid == 0)
		_exit(run_capability_tests());

	while (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR)
			continue;
		ksft_test_result_fail("waitpid() failed: %s\n", strerror(errno));
		ksft_test_result_fail("waitpid() failed: %s\n", strerror(errno));
		return ksft_get_fail_cnt() ? ksft_exit_fail() : ksft_exit_pass();
	}
	if (!WIFEXITED(status)) {
		ksft_test_result_fail("capability test process did not exit\n");
		ksft_test_result_fail("capability test process did not exit\n");
		return ksft_get_fail_cnt() ? ksft_exit_fail() : ksft_exit_pass();
	}

	result = WEXITSTATUS(status);
	if (result == TEST_SETUP_SKIP) {
		ksft_test_result_skip(
			"requires root with CAP_CHECKPOINT_RESTORE and usable non-root IDs\n");
		ksft_test_result_skip(
			"requires root with CAP_CHECKPOINT_RESTORE and usable non-root IDs\n");
	} else if (result == TEST_SETUP_FAIL) {
		ksft_test_result_fail("could not prepare checkpoint capability test\n");
		ksft_test_result_fail("could not prepare checkpoint capability test\n");
	} else {
		if (result & TEST_DENIED_PASS)
			ksft_test_result_pass(
				"set_tid without effective CAP_CHECKPOINT_RESTORE returns EPERM\n");
		else
			ksft_test_result_fail(
				"set_tid without effective CAP_CHECKPOINT_RESTORE did not return EPERM\n");

		if (result & TEST_ALLOWED_PASS)
			ksft_test_result_pass(
				"CAP_CHECKPOINT_RESTORE permits non-root requested PID selection\n");
		else
			ksft_test_result_fail(
				"CAP_CHECKPOINT_RESTORE did not permit non-root requested PID selection\n");
	}

	return ksft_get_fail_cnt() ? ksft_exit_fail() : ksft_exit_pass();
}

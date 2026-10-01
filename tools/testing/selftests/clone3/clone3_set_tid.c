// SPDX-License-Identifier: GPL-2.0

/*
 * Based on Christian Brauner's clone3() example.
 * These tests are assuming to be running in the host's
 * PID namespace.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <linux/capability.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>

#include "../kselftest.h"
#include "clone3_selftests.h"

#ifndef MAX_PID_NS_LEVEL
#define MAX_PID_NS_LEVEL 32
#endif

/*
 * The nested child reports result deltas in wait status: bit 7 marks a
 * valid result, bits 0-2 contain passes, and bits 3-5 contain failures.
 */
#define NS_CHILD_RESULT_VALID		0x80
#define NS_CHILD_RESULT_RESERVED	0x40
#define NS_CHILD_RESULT_COUNT_MASK	0x07
#define NS_CHILD_RESULT_FAIL_SHIFT	3
#define NS_CHILD_TEST_COUNT		4

static int pipe_1[2];
static int pipe_2[2];

static int call_clone3_set_tid(pid_t *set_tid,
			       size_t set_tid_size,
			       int flags,
			       int expected_pid,
			       bool wait_for_it)
{
	int status;
	pid_t pid = -1;

	struct clone_args args = {
		.flags = flags,
		.exit_signal = SIGCHLD,
		.set_tid = ptr_to_u64(set_tid),
		.set_tid_size = set_tid_size,
	};

	pid = sys_clone3(&args, sizeof(struct clone_args));
	if (pid < 0) {
		ksft_print_msg("%s - Failed to create new process\n",
			       strerror(errno));
		return -errno;
	}

	if (pid == 0) {
		int ret;
		char tmp = 0;
		int exit_code = EXIT_SUCCESS;

		ksft_print_msg("I am the child, my PID is %d (expected %d)\n",
			       getpid(), set_tid[0]);
		if (wait_for_it) {
			ksft_print_msg("[%d] Child is ready and waiting\n",
				       getpid());

			/* Signal the parent that the child is ready */
			close(pipe_1[0]);
			ret = write(pipe_1[1], &tmp, 1);
			if (ret != 1) {
				ksft_print_msg(
					"Writing to pipe returned %d", ret);
				exit_code = EXIT_FAILURE;
			}
			close(pipe_1[1]);
			close(pipe_2[1]);
			ret = read(pipe_2[0], &tmp, 1);
			if (ret != 1) {
				ksft_print_msg(
					"Reading from pipe returned %d", ret);
				exit_code = EXIT_FAILURE;
			}
			close(pipe_2[0]);
		}

		if (set_tid[0] != getpid())
			_exit(EXIT_FAILURE);
		_exit(exit_code);
	}

	if (expected_pid == 0 || expected_pid == pid) {
		ksft_print_msg("I am the parent (%d). My child's pid is %d\n",
			       getpid(), pid);
	} else {
		ksft_print_msg(
			"Expected child pid %d does not match actual pid %d\n",
			expected_pid, pid);
		return -1;
	}

	if (waitpid(pid, &status, 0) < 0) {
		ksft_print_msg("Child returned %s\n", strerror(errno));
		return -errno;
	}

	if (!WIFEXITED(status))
		return -1;

	return WEXITSTATUS(status);
}

static void test_clone3_set_tid(pid_t *set_tid,
				size_t set_tid_size,
				int flags,
				int expected,
				int expected_pid,
				bool wait_for_it)
{
	int ret;

	ksft_print_msg(
		"[%d] Trying clone3() with CLONE_SET_TID to %d and 0x%x\n",
		getpid(), set_tid[0], flags);
	ret = call_clone3_set_tid(set_tid, set_tid_size, flags, expected_pid,
				  wait_for_it);
	ksft_print_msg(
		"[%d] clone3() with CLONE_SET_TID %d says :%d - expected %d\n",
		getpid(), set_tid[0], ret, expected);
	if (ret != expected)
		ksft_test_result_fail(
			"[%d] Result (%d) is different than expected (%d)\n",
			getpid(), ret, expected);
	else
		ksft_test_result_pass(
			"[%d] Result (%d) matches expectation (%d)\n",
			getpid(), ret, expected);
}

static int call_clone3_set_tid_args(__u64 set_tid, size_t set_tid_size)
{
	int status;
	pid_t pid;
	struct clone_args args = {
		.exit_signal = SIGCHLD,
		.set_tid = set_tid,
		.set_tid_size = set_tid_size,
	};

	pid = sys_clone3(&args, sizeof(args));
	if (pid < 0)
		return -errno;
	if (pid == 0)
		_exit(EXIT_SUCCESS);
	if (waitpid(pid, &status, 0) < 0)
		return -errno;
	if (!WIFEXITED(status))
		return -ECHILD;

	return WEXITSTATUS(status);
}

static void test_clone3_set_tid_args(const char *name, __u64 set_tid,
				     size_t set_tid_size, int expected)
{
	int ret;

	ksft_print_msg("[%d] Trying clone3() with %s\n", getpid(), name);
	ret = call_clone3_set_tid_args(set_tid, set_tid_size);
	if (ret != expected)
		ksft_test_result_fail("%s: got %d, expected %d\n",
				      name, ret, expected);
	else
		ksft_test_result_pass("%s: got expected %d\n", name, expected);
}

static void test_clone3_set_tid_permission(void)
{
	pid_t pid, set_tid = 1;
	int status;

	pid = fork();
	if (pid < 0) {
		ksft_test_result_fail("fork() failed: %s\n", strerror(errno));
		return;
	}
	if (pid == 0) {
		struct __user_cap_header_struct header = {
			.version = _LINUX_CAPABILITY_VERSION_3,
		};
		struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {};

		if (syscall(SYS_capset, &header, data) < 0)
			_exit(77);
		_exit(call_clone3_set_tid(&set_tid, 1, 0, 0, false) == -EPERM ?
		      EXIT_SUCCESS : EXIT_FAILURE);
	}

	if (waitpid(pid, &status, 0) < 0) {
		ksft_test_result_fail("waitpid() failed: %s\n", strerror(errno));
		return;
	}
	if (!WIFEXITED(status))
		ksft_test_result_fail("Permission test child did not exit\n");
	else if (WEXITSTATUS(status) == 77)
		ksft_test_result_skip("Could not drop capabilities for EPERM test\n");
	else if (WEXITSTATUS(status) == EXIT_SUCCESS)
		ksft_test_result_pass("set_tid without capabilities returns EPERM\n");
	else
		ksft_test_result_fail(
			"set_tid without capabilities did not return EPERM\n");
}

int main(void)
{
	FILE *f;
	char buf;
	char *line = NULL;
	int status, child_result;
	size_t len = 0;
	int pid_max = 0;
	uid_t uid = getuid();
	char proc_path[100] = {0};
	pid_t pid, ns1 = 0, ns2 = 0, ns3 = 0, ns_pid;
	pid_t set_tid[MAX_PID_NS_LEVEL * 2];
	int pass_count_before_ns, fail_count_before_ns;

	if (pipe(pipe_1) < 0 || pipe(pipe_2) < 0)
		ksft_exit_fail_msg("pipe() failed\n");

	ksft_print_header();
	ksft_set_plan(31);

	f = fopen("/proc/sys/kernel/pid_max", "r");
	if (f == NULL)
		ksft_exit_fail_msg(
			"%s - Could not open /proc/sys/kernel/pid_max\n",
			strerror(errno));
	if (fscanf(f, "%d", &pid_max) != 1)
		ksft_exit_fail_msg("Could not read /proc/sys/kernel/pid_max\n");
	fclose(f);
	ksft_print_msg("/proc/sys/kernel/pid_max %d\n", pid_max);

	/* Try invalid settings */
	memset(&set_tid, 0, sizeof(set_tid));
	test_clone3_set_tid(set_tid, MAX_PID_NS_LEVEL + 1, 0, -EINVAL, 0, 0);

	test_clone3_set_tid(set_tid, MAX_PID_NS_LEVEL * 2, 0, -EINVAL, 0, 0);

	test_clone3_set_tid(set_tid, MAX_PID_NS_LEVEL * 2 + 1, 0,
			-EINVAL, 0, 0);

	test_clone3_set_tid(set_tid, MAX_PID_NS_LEVEL * 42, 0, -EINVAL, 0, 0);

	/*
	 * This can actually work if this test running in a MAX_PID_NS_LEVEL - 1
	 * nested PID namespace.
	 */
	test_clone3_set_tid(set_tid, MAX_PID_NS_LEVEL - 1, 0, -EINVAL, 0, 0);

	memset(&set_tid, 0xff, sizeof(set_tid));
	test_clone3_set_tid(set_tid, MAX_PID_NS_LEVEL + 1, 0, -EINVAL, 0, 0);

	test_clone3_set_tid(set_tid, MAX_PID_NS_LEVEL * 2, 0, -EINVAL, 0, 0);

	test_clone3_set_tid(set_tid, MAX_PID_NS_LEVEL * 2 + 1, 0,
			-EINVAL, 0, 0);

	test_clone3_set_tid(set_tid, MAX_PID_NS_LEVEL * 42, 0, -EINVAL, 0, 0);

	/*
	 * This can actually work if this test running in a MAX_PID_NS_LEVEL - 1
	 * nested PID namespace.
	 */
	test_clone3_set_tid(set_tid, MAX_PID_NS_LEVEL - 1, 0, -EINVAL, 0, 0);

	test_clone3_set_tid_args("NULL set_tid with nonzero size", 0, 1,
				 -EINVAL);
	test_clone3_set_tid_args("non-NULL set_tid with zero size",
				 ptr_to_u64(&set_tid[0]), 0, -EINVAL);
	test_clone3_set_tid_args("invalid set_tid pointer", ~(__u64)0, 1,
				 -EFAULT);

	memset(&set_tid, 0, sizeof(set_tid));
	/* Try with an invalid PID */
	set_tid[0] = 0;
	test_clone3_set_tid(set_tid, 1, 0, -EINVAL, 0, 0);

	set_tid[0] = -1;
	test_clone3_set_tid(set_tid, 1, 0, -EINVAL, 0, 0);

	/* Claim that the set_tid array actually contains 2 elements. */
	test_clone3_set_tid(set_tid, 2, 0, -EINVAL, 0, 0);

	/* Try it in a new PID namespace */
	if (uid == 0)
		test_clone3_set_tid(set_tid, 1, CLONE_NEWPID, -EINVAL, 0, 0);
	else
		ksft_test_result_skip("Clone3() with set_tid requires root\n");

	/* Try with a valid PID (1) this should return -EEXIST. */
	set_tid[0] = 1;
	if (uid == 0)
		test_clone3_set_tid(set_tid, 1, 0, -EEXIST, 0, 0);
	else
		ksft_test_result_skip("Clone3() with set_tid requires root\n");

	/* Try it in a new PID namespace */
	if (uid == 0)
		test_clone3_set_tid(set_tid, 1, CLONE_NEWPID, 0, 0, 0);
	else
		ksft_test_result_skip("Clone3() with set_tid requires root\n");

	/* pid_max should fail everywhere */
	set_tid[0] = pid_max;
	test_clone3_set_tid(set_tid, 1, 0, -EINVAL, 0, 0);

	if (uid == 0)
		test_clone3_set_tid(set_tid, 1, CLONE_NEWPID, -EINVAL, 0, 0);
	else
		ksft_test_result_skip("Clone3() with set_tid requires root\n");

	test_clone3_set_tid_permission();

	if (uid != 0) {
		/*
		 * All remaining tests require root. Tell the framework
		 * that all those tests are skipped as non-root.
		 */
		ksft_cnt.ksft_xskip += ksft_plan - ksft_test_num();
		goto out;
	}

	/* Find the current active PID */
	pid = fork();
	if (pid < 0)
		ksft_exit_fail_msg("fork() failed: %s\n", strerror(errno));
	if (pid == 0) {
		ksft_print_msg("Child has PID %d\n", getpid());
		_exit(EXIT_SUCCESS);
	}
	if (waitpid(pid, &status, 0) < 0)
		ksft_exit_fail_msg("Waiting for child %d failed", pid);

	/* After the child has finished, its PID should be free. */
	set_tid[0] = pid;
	test_clone3_set_tid(set_tid, 1, 0, 0, 0, 0);

	/* This should fail as there is no PID 1 in that namespace */
	test_clone3_set_tid(set_tid, 1, CLONE_NEWPID, -EINVAL, 0, 0);

	/*
	 * Creating a process with PID 1 in the newly created most nested
	 * PID namespace and PID 'pid' in the parent PID namespace. This
	 * needs to work.
	 */
	set_tid[0] = 1;
	set_tid[1] = pid;
	test_clone3_set_tid(set_tid, 2, CLONE_NEWPID, 0, pid, 0);

	ksft_print_msg("unshare PID namespace\n");
	if (unshare(CLONE_NEWPID) == -1)
		ksft_exit_fail_msg("unshare(CLONE_NEWPID) failed: %s\n",
				strerror(errno));

	set_tid[0] = pid;

	/* This should fail as there is no PID 1 in that namespace */
	test_clone3_set_tid(set_tid, 1, 0, -EINVAL, 0, 0);

	/* Let's create a PID 1 */
	pass_count_before_ns = ksft_get_pass_cnt();
	fail_count_before_ns = ksft_get_fail_cnt();
	ns_pid = fork();
	if (ns_pid < 0) {
		ksft_test_result_fail("fork() failed: %s\n", strerror(errno));
		goto out;
	}
	if (ns_pid == 0) {
		ksft_print_msg("Child in PID namespace has PID %d\n", getpid());
		set_tid[0] = 2;
		test_clone3_set_tid(set_tid, 1, 0, 0, 2, 0);

		set_tid[0] = 1;
		set_tid[1] = -1;
		set_tid[2] = pid;
		/* This should fail as there is invalid PID at level '1'. */
		test_clone3_set_tid(set_tid, 3, CLONE_NEWPID, -EINVAL, 0, 0);

		set_tid[0] = 1;
		set_tid[1] = 42;
		set_tid[2] = pid;
		/*
		 * This should fail as there are not enough active PID
		 * namespaces. Again assuming this is running in the host's
		 * PID namespace. Not yet nested.
		 */
		test_clone3_set_tid(set_tid, 4, CLONE_NEWPID, -EINVAL, 0, 0);

		/*
		 * This should work and from the parent we should see
		 * something like 'NSpid:	pid	42	1'.
		 */
		test_clone3_set_tid(set_tid, 3, CLONE_NEWPID, 0, 42, true);

		_exit(NS_CHILD_RESULT_VALID |
		      ((ksft_get_fail_cnt() - fail_count_before_ns) <<
		       NS_CHILD_RESULT_FAIL_SHIFT) |
		      (ksft_get_pass_cnt() - pass_count_before_ns));
	}

	close(pipe_1[1]);
	close(pipe_2[0]);
	while (read(pipe_1[0], &buf, 1) > 0) {
		ksft_print_msg("[%d] Child is ready and waiting\n", getpid());
		break;
	}

	snprintf(proc_path, sizeof(proc_path), "/proc/%d/status", pid);
	f = fopen(proc_path, "r");
	if (f == NULL)
		ksft_exit_fail_msg(
			"%s - Could not open %s\n",
			strerror(errno), proc_path);

	while (getline(&line, &len, f) != -1) {
		if (strstr(line, "NSpid")) {
			int i;

			/* Verify that all generated PIDs are as expected. */
			i = sscanf(line, "NSpid:\t%d\t%d\t%d",
				   &ns3, &ns2, &ns1);
			if (i != 3) {
				ksft_print_msg(
					"Unexpected 'NSPid:' entry: %s",
					line);
				ns1 = ns2 = ns3 = 0;
			}
			break;
		}
	}
	fclose(f);
	free(line);
	close(pipe_2[0]);

	/* Tell the clone3()'d child to finish. */
	write(pipe_2[1], &buf, 1);
	close(pipe_2[1]);

	if (waitpid(ns_pid, &status, 0) < 0) {
		ksft_test_result_fail("Waiting for child failed: %s\n",
				      strerror(errno));
		goto out;
	}

	if (!WIFEXITED(status)) {
		ksft_test_result_fail("Child did not exit normally\n");
		goto out;
	}

	child_result = WEXITSTATUS(status);
	if (!(child_result & NS_CHILD_RESULT_VALID) ||
	    (child_result & NS_CHILD_RESULT_RESERVED) ||
	    ((child_result & NS_CHILD_RESULT_COUNT_MASK) +
	     ((child_result >> NS_CHILD_RESULT_FAIL_SHIFT) &
	      NS_CHILD_RESULT_COUNT_MASK) != NS_CHILD_TEST_COUNT)) {
		ksft_test_result_fail("Invalid nested test result %#x\n",
				      child_result);
		goto out;
	}

	ksft_cnt.ksft_pass += child_result & NS_CHILD_RESULT_COUNT_MASK;
	ksft_cnt.ksft_fail +=
		(child_result >> NS_CHILD_RESULT_FAIL_SHIFT) &
		NS_CHILD_RESULT_COUNT_MASK;

	if (ns3 == pid && ns2 == 42 && ns1 == 1)
		ksft_test_result_pass(
			"PIDs in all namespaces as expected (%d,%d,%d)\n",
			ns3, ns2, ns1);
	else
		ksft_test_result_fail(
			"PIDs in all namespaces not as expected (%d,%d,%d)\n",
			ns3, ns2, ns1);
out:
	return !ksft_get_fail_cnt() ? ksft_exit_pass() : ksft_exit_fail();
}

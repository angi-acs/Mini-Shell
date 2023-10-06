// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1
#define PATH_MAX    4096

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */
	return chdir(get_word(dir));
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */
	exit(0);
	return 0; /* TODO: Replace with actual exit code. */
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	DIE(!s, "parse_simple - s null");

	/* TODO: If builtin command, execute the command. */
	char *word = get_word(s->verb);

	if (strcmp(word, "exit") == 0 || 
			strcmp(word, "quit") == 0) {
		return shell_exit();
	}

	if (strcmp(word, "cd") == 0) {
		if (!s->params) {
			return 0;

		} else {
			if (s->out) {
				/* Save stdout fd */
				int old_stdout = dup(STDOUT_FILENO);
				close(STDOUT_FILENO);

				int flags = O_WRONLY | O_CREAT;
				if (s->io_flags == IO_REGULAR) {
					flags |= O_TRUNC;
				} else if (s->io_flags == IO_OUT_APPEND) {
					flags |= O_APPEND;
				}

				int out = open(get_word(s->out), flags, 0644);
				DIE(out < 0, "parse_simple - out cd open error");

				int ret = dup2(out, STDOUT_FILENO);
				DIE(ret < 0, "parse_simple - out cd dup2 error");
				close(out);

				/* Restore stdout */
				dup2(old_stdout, STDOUT_FILENO);
			}

			return shell_cd(s->params);
		}
	}

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */

	if (strchr(word, '=')) {
		char *name = strtok(word, "=");
		char *value = strtok(NULL, "=");
		return setenv(name, value, 1);
	}

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	int size, ret, status, in, out, err, flags;

	pid_t pid = fork();
	DIE(pid < 0, "parse_simple - fork error");

	/* Child process */
	if (pid == 0) {
		if (s->in) {
			in = open(get_word(s->in), O_RDONLY);
			DIE(in < 0, "parse_simple - in open error");

			ret = dup2(in, STDIN_FILENO);
			DIE(ret < 0, "parse_simple - in dup2 error");
			close(in);
		}

		if (s->out) {
			flags = O_WRONLY | O_CREAT;
			if (s->io_flags == IO_REGULAR) {
				flags |= O_TRUNC;
			} else if (s->io_flags == IO_OUT_APPEND) {
				flags |= O_APPEND;
			}

			out = open(get_word(s->out), flags, 0644);
			DIE(out < 0, "parse_simple - out open error");

			ret = dup2(out, STDOUT_FILENO);
			DIE(ret < 0, "parse_simple - out dup2 error");

			if (s->err && strcmp(get_word(s->out), get_word(s->err)) == 0) {
				ret = dup2(out, STDERR_FILENO);
				DIE(ret < 0, "parse_simple - out err 2 dup2 error");
				close(out);

				/* Skip err redirection because it has already been handled */
				goto same_file;
			}

			close(out);
		}
		
		if (s->err) {
			flags = O_WRONLY | O_CREAT;
			if (s->io_flags == IO_REGULAR) {
				flags |= O_TRUNC;
			} else if (s->io_flags == IO_ERR_APPEND) {
				flags |= O_APPEND;
			}

			err = open(get_word(s->err), flags, 0644);
			DIE(err < 0, "parse_simple - err open error");

			ret = dup2(err, STDERR_FILENO);
			DIE(ret < 0, "parse_simple - err dup2 error");

			close(err);
		}

same_file:
		ret = execvp(word, get_argv(s, &size));
		if (ret < 0) {
			printf("Execution failed for '%s'\n", word);
			exit(ret);
		}
		
	} else {
		/* Parent process */
        waitpid(pid, &status, 0);
	}

	/* Only the last 8 bits that actually contain the status */
	return WEXITSTATUS(status);
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	int ret, status_cmd1, status_cmd2;

	pid_t pid_cmd1 = fork();
	DIE(pid_cmd1 < 0, "run_in_parallel 1 - fork error");

	/* Child process cmd1 */
	if (pid_cmd1 == 0) {
		ret = parse_command(cmd1, level, father);
		exit(ret);
	}

	pid_t pid_cmd2 = fork();
	DIE(pid_cmd2 < 0, "run_in_parallel 2 - fork error");

	/* Child process cmd2 */
	if (pid_cmd2 == 0) {
		ret = parse_command(cmd2, level, father);
		exit(ret);
	}

	waitpid(pid_cmd1, &status_cmd1, 0);
	waitpid(pid_cmd2, &status_cmd2, 0);

	/* If a command returns a non-zero status, the overall status should be non-zero */
	return WEXITSTATUS(status_cmd1) | WEXITSTATUS(status_cmd2);
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	int pipefd[2];
	int status, ret;

	ret = pipe(pipefd);
	DIE(ret < 0, "run_on_pipe pipe error");

	/* Save stdin fd */
	int old_stdin = dup(STDIN_FILENO);

	/* The pipe will be from child to parent, 
	so the child can finish its execution before the parent */
	pid_t pid = fork();

	/* Child process */
	if (pid == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);

		ret = parse_command(cmd1, level, father);
		exit(ret);

	} else {
		/* Parent process */
		close(pipefd[1]);
		dup2(pipefd[0], STDIN_FILENO);

		ret = parse_command(cmd2, level, father);

		close(pipefd[0]);
		close(pipefd[1]);

		/* Restore stdin */
		dup2(old_stdin, STDIN_FILENO);
		close(old_stdin);

		waitpid(pid, &status, 0);

		/* Return the exit status of the second command */
		return ret; 
	}

	return true;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	DIE(!c, "parse_command - c null");

	if (c->op == OP_NONE) {
		/* TODO: Execute a simple command. */
		return parse_simple(c->scmd, level, father);
		/* TODO: Replace with actual exit code of command. */
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		parse_command(c->cmd1, level, father);
		return parse_command(c->cmd2, level, father);
		break;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		return run_in_parallel(c->cmd1, c->cmd2, level, father);
		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		if (parse_command(c->cmd1, level, father)) {
			return parse_command(c->cmd2, level, father);
		}
		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		if (parse_command(c->cmd1, level, father) == 0) {
			return parse_command(c->cmd2, level, father);
		}
		break;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		return run_on_pipe(c->cmd1, c->cmd2, level, father);
		break;

	default:
		return SHELL_EXIT;
	}

	return 0; /* TODO: Replace with actual exit code of command. */
}

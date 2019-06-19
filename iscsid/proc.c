/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "iscsid.h"

char procPath[4096];
char procData[4096];

int proc_read_string(const char *name, char **result)
{
	char *ptr;
	int len, size, fd;
	int res = 0;

	ptr = NULL;

	len = strlen(procPath);
	procPath[len] = '/';
	strcpy(procPath + len + 1, name);

	fd = open(procPath, O_RDONLY);
	if (fd >= 0) {
		size = read(fd, procData, sizeof(procData) - 1);
		if (size >= 0) {
			procData[size] = 0;
			ptr = strchr(procData, '\n');
			size = ptr ? ptr - procData : size;
			ptr = xmalloc(size + 1);
			memcpy(ptr, procData, size);
			ptr[size] = 0;
			*result = ptr;
			res = 1;
		}
		close(fd);
	}

	procPath[len] = 0;
	return res;
}

int proc_read_u64(const char *name, u64 *result)
{
	char *ptr;
	int len, size, fd;
	int res = 0;

	ptr = NULL;

	len = strlen(procPath);
	procPath[len] = '/';
	strcpy(procPath + len + 1, name);

	fd = open(procPath, O_RDONLY);
	if (fd >= 0) {
		size = read(fd, procData, sizeof(procData) - 1);
		if (size >= 0) {
			procData[size] = 0;
			*result = strtoull(procData, NULL, 0);
			res = 1;
		}
		close(fd);
	}

	procPath[len] = 0;
	return res;
}

int proc_read_u32(const char *name, u32 *result)
{
	char *ptr;
	int len, size, fd;
	int res = 0;

	ptr = NULL;

	len = strlen(procPath);
	procPath[len] = '/';
	strcpy(procPath + len + 1, name);

	fd = open(procPath, O_RDONLY);
	if (fd >= 0) {
		size = read(fd, procData, sizeof(procData) - 1);
		if (size >= 0) {
			procData[size] = 0;
			*result = strtoul(procData, NULL, 0);
			res = 1;
		}
		close(fd);
	}

	procPath[len] = 0;
	return res;
}

int proc_read_u16(const char *name, u16 *result)
{
	char *ptr;
	int len, size, fd;
	int res = 0;

	ptr = NULL;

	len = strlen(procPath);
	procPath[len] = '/';
	strcpy(procPath + len + 1, name);

	fd = open(procPath, O_RDONLY);
	if (fd >= 0) {
		size = read(fd, procData, sizeof(procData) - 1);
		if (size >= 0) {
			procData[size] = 0;
			*result = strtoul(procData, NULL, 0);
			res = 1;
		}
		close(fd);
	}

	procPath[len] = 0;
	return res;
}

int proc_read_bool(const char *name, int *result, int mask)
{
	char *ptr;
	int len, size, fd;
	int res = 0;

	ptr = NULL;

	len = strlen(procPath);
	procPath[len] = '/';
	strcpy(procPath + len + 1, name);

	fd = open(procPath, O_RDONLY);
	if (fd >= 0) {
		size = read(fd, procData, sizeof(procData) - 1);
		if (size >= 0) {
			procData[size] = 0;
			res = 1;
			if (!memcmp(procData, "yes", 3))
				*result |= mask;
			else if (!memcmp(procData, "no", 2))
				*result &= ~mask;
			else if (isdigit(procData[0])) {
				if (atoi(procData))
					*result |= mask;
				else
					*result &= ~mask;
			} else
				res = 0;
		}
		close(fd);
	}

	procPath[len] = 0;
	return res;
}

void proc_write(const char *name, const char *fmt,...)
{
	int len, fd;
	va_list ap;

	len = strlen(procPath);
	procPath[len] = '/';
	strcpy(procPath + len + 1, name);

	fd = open(procPath, O_WRONLY);
	if (fd >= 0) {
		va_start(ap, fmt);
		vsprintf(procData, fmt, ap);
		va_end(ap);

		write(fd, procData, strlen(procData));
		close(fd);
	}

	procPath[len] = 0;
}

void proc_write_u64(const char *name, u64 val)
{
	proc_write(name, "%Lu", val);
}

void proc_write_u32(const char *name, u32 val)
{
	proc_write(name, "%u", val);
}

void proc_write_u16(const char *name, u16 val)
{
	proc_write(name, "%u", val);
}

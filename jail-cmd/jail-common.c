/*
 * Copyright (C) 2017 Ruilin Peng (Nick) <pymumu@gmail.com>
 */

#include "jail-cmd.h"

void set_sock_opt(int sock)
{
	int on = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

}

int normalize_path(char *path) 
{
	char *temp = NULL;
	char *begin = path;
	char *nextadd = path;
	char *nextcmp = path;

	/*  skip space */
	while (*nextcmp == '\x20') {
		nextcmp++;
	}

	/*  if not start with /, return 0 */
	if (*nextcmp != '/' || nextcmp[0] == '\0') {
		return 0;
	}


	*nextadd = *nextcmp;
	nextadd++;
	nextcmp++;

	while (*nextcmp) {
		if (*nextcmp == '.') {
			if (nextcmp[1] == '/' || nextcmp[1] == '\0') {
				nextcmp += 2;
				continue;
			} else if (nextcmp[1] == '.' && (nextcmp[2] == '/' || nextcmp[2] == '\0')) {
				temp = nextadd - 1;
				if (temp == begin) {
					nextcmp += 3;
					continue;
				}

				while (*(--temp) != '/') {
				}

				nextadd = temp + 1;
				nextcmp += 3;
				continue;
			}
		} else if (*nextcmp == '/') {
			nextcmp++;
			continue;
		}

		while (*nextcmp && (*nextadd++ = *nextcmp++) != '/') {
		}
	}

	temp = nextadd;
	if (*(temp - 1) == '/') {
		temp--;
	}

	while (*temp != 0) {
		*temp++ = 0;
	}

	return nextadd - begin;
}

int load_config(char *config_file, config_callback call_back)
{
	char buff[MAX_LINE_LEN];
	char filed1[MAX_LINE_LEN];
	char filed2[MAX_LINE_LEN];
	int filedNum = 0;

	FILE *fp = NULL;

	fp = fopen(config_file, "r");
	if (fp == NULL) {
		fprintf(stderr, "open %s failed, %s\n", config_file, strerror(errno));
		goto errout;
	}

	while (fgets(buff, MAX_LINE_LEN, fp)) {
		filedNum = sscanf(buff, "%1024s %1024s", filed1, filed2);
		if (filedNum < 0) {
			continue;
		}

		/*  comment line */
		if (filed1[0] == '#') {
			continue;
		}

		if (filedNum != 2) {
			continue;
		}

		if (call_back(filed1, filed2) != 0) {
			goto errout;
		}
	}

	fclose(fp);
	return 0;
errout:
	if (fp) {
		fclose(fp);
	}
	return -1;
}


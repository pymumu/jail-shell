#include "jailed-cmd.h"

void set_sock_opt(int sock)
{
	int on = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

}

char *normalize_path(char *path) 
{
	char *next = path;
	char *start ;
	int is_slash = 0;
	int first_dot = 0;
	int second_dot = 0;
	int dot_dir = 0;

	for (next = path; *next; next++) {
		/*  if start with /, then set slash start flag. */
		if (*next == '/' && is_slash == 0) {

			is_slash = 1;
			start = next;
			continue;
		}

		/*  if not slash, skip and check. */
		if (*next != '/' && is_slash == 0) {
			continue;
		}

		if (*next != '.' && *next != '/' && is_slash == 1) {
			is_slash = 0;
			continue;
		}

		if (*next == '/' && is_slash == 1) {
			/*  if /.../  */
			if (dot_dir) {
				second_dot = 0;
				first_dot = 0;
				dot_dir = 0;
				start = next;
				continue;
			}

			/*  if //  */
			if (first_dot == 0) {
				strcpy(start, next);
				next = start;
				continue;
			}

			/*  if /../  */
			if (second_dot == 1) {
				second_dot = 0;
				first_dot = 0;

				/*  find previous slash */
				while (start > path) {
					start--;
					if (*start == '/') {
						break;
					}
				}

				strcpy(start, next);
				next = start;
				continue;
			}
			
			/* if /./ */
			if (first_dot == 1 ) {
				first_dot = 0;
				second_dot = 0;
				strcpy(start, next);
				next = start;
				continue;
			}
			continue;
		}

		/*  if is slash + ., count dot number */
		if (*next == '.') {
			if (first_dot == 0) {
				first_dot = 1;
			} else if (second_dot == 0) {
				second_dot = 1;
			} else {
				/* if dot number is more than two ,then this is a dir. */
				dot_dir = 1;
			}
			continue;
		}

	}

	return path;
}

/*
 * Linux-PAM session chroot()er
 * account, session, authentication
 *
 * $Id: pam_chroot.c,v 1.8 2007/09/30 18:54:07 schmolli Exp $
 */

#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>

#define  PAM_SM_AUTH
#define  PAM_SM_ACCOUNT
#define  PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

/* default location of the pam_chroot config file */
#define CONFIG  "/etc/security/chroot.conf"

/* max length (bytes) of line in config file */
#define LINELEN         1024
/* max length (bytes) of a GID string representation */
#define MAX_GID_LEN     6
/* maximum number of groups we handle */
#define MAX_GROUPS      64

/* defines for flags */
#define _PAM_OPTS_NOOPTS        0x0000
#define _PAM_OPTS_DEBUG         0x0001
#define _PAM_OPTS_SILENT        0x0002
#define _PAM_OPTS_NOTFOUNDFAILS 0x0004
#define _PAM_OPTS_NO_CHROOT     0x0008
#define _PAM_OPTS_USE_REGEX     0x0010
#define _PAM_OPTS_USE_EXT_REGEX 0x0030 /* includes _PAM_OPTS_USE_REGEX */
#define _PAM_OPTS_USE_GROUPS    0x0040
#define _PAM_OPTS_SECCHECKS     0x0080

/* defines for (internal) return values */
#define _PAM_CHROOT_INTERNALERR         -2
#define _PAM_CHROOT_SYSERR              -1
#define _PAM_CHROOT_OK                  0
#define _PAM_CHROOT_USERNOTFOUND        1
#define _PAM_CHROOT_INCOMPLETE          2


typedef struct _pam_opts {
  int16_t flags;        /* combined option flags */
  char* chroot_dir;     /* where to chroot to */
  char* conf;           /* name of pam_chroot config file */
  char* module;         /* module currently being processed */
} _opts;

static void _pam_log(int err, const char *format, ...) {
  va_list args;

  va_start(args, format);
  openlog("pam_chroot", LOG_PID, LOG_AUTHPRIV);
  vsyslog(err, format, args);
  va_end(args);
  closelog();
}

/* initialize opts to a standard known state */
int _pam_opts_init(_opts* opts) {
  if (NULL == opts) {
    _pam_log(LOG_ERR, "%s: NULL opts pointer", __FUNCTION__);
    return _PAM_CHROOT_INTERNALERR;
  }

  opts->flags = _PAM_OPTS_NOOPTS;
  opts->chroot_dir = NULL;

  opts->conf = x_strdup(CONFIG);
  if (NULL == opts->conf) {
    _pam_log(LOG_ERR, "strdup: %s", strerror(errno));
    return _PAM_CHROOT_SYSERR;
  }

  return _PAM_CHROOT_OK;
}

/* configure opts per the passed flags and cmd line args */
int _pam_opts_config(_opts* opts, int flags, int argc, const char** argv) {
  int i;

  if (NULL == opts) {
    _pam_log(LOG_ERR, "%s: NULL opts pointer", __FUNCTION__);
    return _PAM_CHROOT_INTERNALERR;
  }

  if (flags & PAM_SILENT) {
    opts->flags = opts->flags | _PAM_OPTS_SILENT;
  }
  if ((flags & PAM_DISALLOW_NULL_AUTHTOK) &&
     (!strcmp(opts->module, "auth") || !strcmp(opts->module, "account"))) {
    opts->flags = opts->flags | _PAM_OPTS_NOTFOUNDFAILS;
  }

  /* parse command line args */
  for (i = 0; i < argc; i++) {
    if (!strcmp(argv[i], "debug")) {
      opts->flags = opts->flags | _PAM_OPTS_DEBUG;
    } else if (!strcmp(argv[i], "no_warn")) {
      opts->flags = opts->flags | _PAM_OPTS_SILENT;
    } else if (!strcmp(argv[i], "use_first_pass") ||
               !strcmp(argv[i], "try_first_pass") ||
               !strcmp(argv[i], "use_mapped_pass")) {
      /* ignore these, pam_chroot doesn't care about passwds */
    } else if (!strcmp(argv[i], "no_chroot")) {
      opts->flags = opts->flags | _PAM_OPTS_NO_CHROOT;
    } else if (!strcmp(argv[i], "use_regex")) {
      opts->flags = opts->flags | _PAM_OPTS_USE_REGEX;
    } else if (!strcmp(argv[i], "use_ext_regex")) {
      opts->flags = opts->flags | _PAM_OPTS_USE_EXT_REGEX;
    } else if (!strcmp(argv[i], "use_groups")) {
      opts->flags = opts->flags | _PAM_OPTS_USE_GROUPS;
    } else if (!strcmp(argv[i], "sec_checks")) {
      opts->flags = opts->flags | _PAM_OPTS_SECCHECKS;
    } else if (!strncmp(argv[i], "notfound=", 9)) {
      if (!strcmp(argv[i] + 9, "success")) {
        opts->flags = opts->flags & (~_PAM_OPTS_NOTFOUNDFAILS);
      } else if (!strcmp(argv[i] + 9, "failure")) {
        opts->flags = opts->flags | _PAM_OPTS_NOTFOUNDFAILS;
      } else {
        _pam_log(LOG_ERR, "bad config option: \"%s\"", argv[i]);
      }
    } else if (!strncmp(argv[i], "onerr=", 6)) {
      if (!strcmp(argv[i] + 6, "succeed")) {
        opts->flags = opts->flags & (~_PAM_OPTS_NOTFOUNDFAILS);
      } else if (!strcmp(argv[i] + 6, "fail")) {
        opts->flags = opts->flags | _PAM_OPTS_NOTFOUNDFAILS;
      } else {
        _pam_log(LOG_ERR, "bad config option: \"%s\"", argv[i]);
      }
    } else if (!strncmp(argv[i], "chroot_dir=", 11)) {
      if (*(argv[i] + 11) == '\0') {
        _pam_log(LOG_ERR, "bad config option: \"%s\": specify a directory",
                 argv[i]);
      } else if (NULL != opts->chroot_dir) {
        _pam_log(LOG_ERR, "bad config option: \"%s\": chroot dir already set",
                 argv[i]);
      } else {
        opts->chroot_dir = x_strdup(argv[i] + 11);
        if (NULL == opts->chroot_dir) {
          _pam_log(LOG_ERR, "strdup: %s", strerror(errno));
        }
      }
    } else {
      _pam_log(LOG_ERR, "unrecognized config option: \"%s\"", argv[i]);
    }
  }

  return _PAM_CHROOT_OK;
}

/* free the allocated memory of a struct _pam_opts */
int _pam_opts_free(_opts* opts) {
  if (NULL == opts) {
    _pam_log(LOG_ERR, "%s: NULL opts pointer", __FUNCTION__);
  }
  _pam_drop(opts->chroot_dir);
  _pam_drop(opts->conf);

  return _PAM_CHROOT_OK;
}

/* if the system doesn't have getgrouplist(), then I have to do it myself */
#ifndef HAVE_GETGROUPLIST
#define _PAM_GETUGROUPS _pam_getugroups
/* *user is the user to collect info on
 * gid is a gid to include in the grplist
 * *grps is the array of gid_t to return the grplist in (if not NULL)
 * *ngrps is the max number of gid_t to return in grplist AND where to 
 *   store the actual number of gid_t returned
 *
 * return -1 if *ngrps is too small
 */
int _pam_getugroups(const char *user, gid_t gid, gid_t *grps, int *ngrps) {
  struct group *grp;
  int gcount = 0;
  char **uptr;

  if (NULL == user || NULL == ngrps) { return -1; }
  if (0 > *ngrps || 0 > gid) { return -1; }

  if (gcount < *ngrps) {
    if (NULL != grps) { grps[gcount] = gid; }
    gcount++;
  } else {
    *ngrps = gcount;
    endgrent();
    return -1;
  }

  setgrent();
  while(NULL != (grp = getgrent())) {
    if (NULL == grp->gr_name || NULL == grp->gr_mem) { continue; }

    /* do not add gids more than once, do not do this check if grps is NULL */
    /* yes, that is incorrect, but it is harder to do it correctly, and since
     * we are just counting, for the NULL case, it is unlikely to cause a
     * real problem in reasonable circumstances */
    if (NULL != grps) {
      int i;
      for (i = 0 ; i < gcount ; i++) {
        if (grp->gr_gid == grps[i]) { i = -1; break; }
      }
      if (-1 == i) { continue; }
    }

    for (uptr = grp->gr_mem ; NULL != *uptr ; uptr++) {
      if (0 != strcmp(*uptr, user)) { continue; }

      if (gcount < *ngrps) {
        if (NULL != grps) { grps[gcount] = grp->gr_gid; }
        gcount++;
      } else {
        *ngrps = gcount;
        endgrent();
        return -1;
      }
    }
  }
  endgrent();
  *ngrps = gcount;
  return gcount;
}
#else
#define _PAM_GETUGROUPS getgrouplist
#endif

/* generate a list of group names from a list of gids */
char** _pam_get_groups(const char* user, _opts* opts) {
  int i, ret, ngroups = MAX_GROUPS;
  struct group* grp;
  struct passwd* pwd;
  gid_t *gids;
  char **groups;

  pwd = getpwnam(user);
  if (pwd == NULL) {
    _pam_log(LOG_ERR, "%s: user \"%s\" not a valid username", opts->module,
             user);
    return NULL;
  }

  /* get a list of all the gids for this username */
  _PAM_GETUGROUPS(pwd->pw_name, pwd->pw_gid, NULL, &ngroups);
  if (0 >= ngroups) {
    _pam_log(LOG_ERR, "%s: error fetching groups for user \"%s\"",
             opts->module, user);
    return NULL;
  }
  gids = (gid_t*) malloc(ngroups*sizeof(gid_t));
  if (NULL == gids) {
    _pam_log(LOG_ERR, "%s: %s: malloc: %s", opts->module, __FUNCTION__,
             strerror(errno));
    return NULL;
  }
  ret = _PAM_GETUGROUPS(pwd->pw_name, pwd->pw_gid, gids, &ngroups);
  if (-1 == ret) {
    _pam_log(LOG_WARNING,
             "%s: %s: _PAM_GETUGROUPS found more gids on second run",
             opts->module, __FUNCTION__);
  }
  if (0 >= ngroups) {
    _pam_log(LOG_ERR,
             "%s: %s: _PAM_GETUGROUPS returned no groups for user \"%s\"",
             opts->module, __FUNCTION__, user);
    _pam_drop(gids);
    return NULL;
  }

  /* resolve gids into grpnams */
  groups = (char**)malloc((ngroups+1)*sizeof(char*));
  if (NULL == groups) {
    _pam_log(LOG_ERR, "%s: %s: malloc: %s", opts->module, __FUNCTION__,
             strerror(errno));
    _pam_drop(gids);
    return NULL;
  }
  for (i = 0; i < ngroups ; i++) {
    grp = getgrgid(gids[i]);
    if (NULL == grp) {
      char gid_as_str[MAX_GID_LEN + 1];
      _pam_log(LOG_DEBUG, "%s: no grnam for gid %d", opts->module, gids[i]);
      snprintf(gid_as_str, MAX_GID_LEN + 1, "%d", gids[i]);
      /* safe to use strdup here instead of x_strdup because gid_as_str is
       * statically allocated */
      groups[i] = strdup(gid_as_str);
    } else {
      groups[i] = x_strdup(grp->gr_name);
    }
  }
  groups[i] = NULL;
  _pam_drop(gids);

  return groups;
}

/* helper function to free group list */
void _pam_free_groups(char **groups) {
  int i = 0;

  if (NULL == groups) { return; }
  while(NULL != groups[i]) {
    _pam_drop(groups[i]);
    i++;
  }
  _pam_drop(groups);
}

/* verify that the arguement path is root owned and not writable by
 * group or other
 * return 0 if ok, 1 if not, -1 on system error */
int _pam_check_path_perms(char *path, _opts* opts) {
  int i = 0, rslt = 0;
  char save;
  struct stat st;

  path = x_strdup(path);
  if (NULL == path) {
    _pam_log(LOG_ERR, "strdup: %s", strerror(errno));
    return -1;
  }

  while('\0' != path[i]) {
    if ('/' == path[i]) {
      save = path[i + 1];
      path[i + 1] = '\0';

      if (-1 == stat(path, &st)) {
        _pam_log(LOG_ERR, "stat(%s): %s", path, strerror(errno));
        rslt = -1;
        break;
      }

      if ((0 != st.st_uid) || (st.st_mode & (S_IWGRP | S_IWOTH))) {
        _pam_log(LOG_ERR, "bad ownership/perms on %s", path);
        rslt = 1;
        break;
      }
      path[i + 1] = save;
    }
    i++;
  }
  if ((NULL != opts) && (opts->flags & _PAM_OPTS_DEBUG)) {
    _pam_log(LOG_NOTICE, "%s: ownership/perms ok on %s", opts->module, path);
  }

  _pam_drop(path);
  return rslt;
}

/* expand chroot path */
/* path - string to expand
 * user - username, for %u expansion
 * grp - group, for %g expansion
 * match - name entry that was matched
 * matchptr - array of regmatch_t containing matched substrings (assume
 *   at least 10 items in array)
 */
char* _pam_expand_chroot_dir(const char* path, const char* user,
                             const char* grp, const char* match,
                             regmatch_t* matchptr, _opts* opts) {
  char ref;  /* ref char */
  char *pos;  /* ref position */
  char *exp;  /* expanded path */
  int reflen;  /* length of expanded path */
  int refnum;  /* number of regex backreference */
  int offset = 0;  /* search offset */

  if (NULL == path || NULL == user || NULL == opts) {
    return NULL;
  } else if (NULL == grp && (opts->flags & _PAM_OPTS_USE_GROUPS)) {
    return NULL;
  }

  exp = x_strdup(path);
  if (NULL == exp) {
    _pam_log(LOG_ERR, "%s: strdup: %s", opts->module, strerror(errno));
    return NULL;
  }

  while(NULL != (pos = strchr(exp + offset, '%'))) {
    offset = pos - exp;  /* save for post-realloc */
    reflen = 0;
    ref = *(pos + 1);

    if ('u' == tolower(ref)) { /* %u found */
      reflen = strlen(user);
      exp = (char*) realloc(exp, strlen(exp) + reflen - 1);
      if (NULL == exp) { break; }
      pos = exp + offset;
      memmove(pos + reflen, pos + 2, strlen(pos + 2) + 1);
      memcpy(pos, user, reflen);

    } else if ('g' == tolower(ref)) { /* %g found */
      reflen = strlen(grp);
      exp = (char*) realloc(exp, strlen(exp) + reflen - 1);
      if (NULL == exp) { break; }
      pos = exp + offset;
      memmove(pos + reflen, pos + 2, strlen(pos + 2) + 1);
      memcpy(pos, grp, reflen);

    } else if (isdigit(ref)) { /* backreference (%1...%9) found */
      if (NULL == match) {
        _pam_log(LOG_ERR,
                 "%s: backreference \"%%%c\" found, but subject of match is "
                 "NULL", opts->module, ref);
        _pam_drop(exp);
        return NULL;
      }

      refnum = ref - '0';
      if (-1 != matchptr[refnum].rm_so) { /* submatch exists */
        reflen = matchptr[refnum].rm_eo - matchptr[refnum].rm_so;
        exp = (char*) realloc(exp, strlen(exp) + reflen + 1);
        if (NULL == exp) { break; }
        pos = exp + offset; 
        memmove(pos + reflen, pos + 2, strlen(pos + 2) + 1);
        memcpy (pos, match + matchptr[refnum].rm_so, reflen);
      } else {
        _pam_log(LOG_ERR,
                 "%s: no submatch corresponding to backreference \"%%%c\"",
                 opts->module, ref);
        _pam_drop(exp);
        return NULL;
      }

    } else if ('%' == ref) { /* %% found */
      memmove(pos, pos + 1, strlen(pos) + 1);
      reflen = 1;

    } else { /* unknown ref */
      _pam_log(LOG_ERR, "%s: unknown reference \"%%%c\"", opts->module, ref);
      _pam_drop(exp);
      return NULL;
    }

    offset += reflen; /* skip past what we just copied */
  }

  if (NULL == exp) { /* catch realloc errors - don't forget to free old exp! */
    _pam_log(LOG_ERR, "%s: realloc: %s", opts->module, strerror(errno));
    free(pos - offset);
    return NULL;
  }

  if (opts->flags & _PAM_OPTS_DEBUG) {
    _pam_log(LOG_NOTICE, "%s: expanded path \"%s\" -> \"%s\"", opts->module,
             path, exp);
  }
  return exp;
}

/* parse the chroot.conf to find chroot_dir */
int _pam_get_chrootdir(const char* user, _opts* opts) {
  FILE* conf;
  char conf_line[LINELEN];
  int lineno, err, name_is_group, regflags = REG_ICASE, i;
  char *name, *mark, *group = NULL, **group_list = NULL;

  if (opts->flags & _PAM_OPTS_SECCHECKS) {
    /* don't need to distinguish the errors for now */
    if (0 != _pam_check_path_perms(opts->conf, opts)) {
      return _PAM_CHROOT_SYSERR;
    }
  }
  if (!(conf = fopen(opts->conf, "r"))) {
    _pam_log(LOG_ERR, "%s: fopen(%s): %s", opts->module, opts->conf,
             strerror(errno));
    opts->chroot_dir = NULL;
    return _PAM_CHROOT_SYSERR;
  }

  if (opts->flags & _PAM_OPTS_USE_GROUPS) {
    group_list = _pam_get_groups(user, opts);
    if (NULL == group_list) { /* probably some kind of malloc error */
      fclose(conf);
      return _PAM_CHROOT_SYSERR;
    } else {
      group = group_list[0];
    }
  }

  lineno = 0; err = 0;
  while(fgets(conf_line, LINELEN, conf)) {
    ++lineno;

    /* ignore comments and blank lines */
    if ((mark = strchr(conf_line, '#'))) { *mark = 0; }
    if (!(name = strtok(conf_line, " \t\r\n"))) { continue; }

    /* ignore lines that contain usernames/regexps but not directories */
    if (!(mark = strtok(NULL, " \t\r\n"))) {
      _pam_log(LOG_ERR, "%s: %s %d: no directory", opts->module, opts->conf,
               lineno);
      continue;
    }

    /* is it a group? */
    name_is_group = 0;
    if ('@' == name[0]) {
      if (opts->flags & _PAM_OPTS_USE_GROUPS) {
        name_is_group = 1;
        name++;
      } else {
        _pam_log(LOG_ERR,
                 "%s: %s %d: found @group style syntax, but use_groups has "
                 "not been turned on", opts->module, opts->conf, lineno);
        fclose(conf);
        return _PAM_CHROOT_SYSERR;
      }
    }

    if (opts->flags & _PAM_OPTS_USE_REGEX) {
      regex_t name_regex;
      regmatch_t matchptr[10];
      char const* match = NULL;
      if (opts->flags & _PAM_OPTS_USE_EXT_REGEX) {
        regflags |= REG_EXTENDED;
      }

      if (0 != (err = regcomp(&name_regex, name, regflags))) {
        size_t len = regerror(err, &name_regex, NULL, 0);
        char *errbuf = malloc(len);
        if (NULL == errbuf) {
          _pam_log(LOG_ERR, "%s: %s: malloc: %s", opts->module, __FUNCTION__,
                   strerror(errno));
          if (opts->flags & _PAM_OPTS_USE_GROUPS) {
            _pam_free_groups(group_list);
          }
          regfree(&name_regex);
          fclose(conf);
          return _PAM_CHROOT_SYSERR;
        }
        regerror(err, &name_regex, errbuf, len);
        _pam_log(LOG_ERR, "%s: %s %d: illegal regex \"%s\": %s", opts->module,
                 opts->conf, lineno, name, errbuf);

        free(errbuf);
        regfree(&name_regex);
        continue;  /* with the next line */
      }

      if (1 == name_is_group) {
        for (i = 0; NULL != group_list[i]; i++) {
          match = group_list[i];
          err = regexec(&name_regex, match, 10, matchptr, 0);
          if (0 == err) { break; }
        }
      } else {
        match = user;
        err = regexec(&name_regex, match, 10, matchptr, 0);
      }
      regfree(&name_regex);

      if (0 == err) {
        fclose(conf);

        opts->chroot_dir = _pam_expand_chroot_dir(mark, user, group, match,
                                                  matchptr, opts);
        if (NULL == opts->chroot_dir) {
          _pam_log(LOG_ERR, "%s: unable to expand chroot_dir", opts->module);
          _pam_free_groups(group_list);
          return _PAM_CHROOT_SYSERR;
        } 
        if (opts->flags & _PAM_OPTS_DEBUG) {
          _pam_log(LOG_NOTICE, "%s: found chroot_dir \"%s\" for user \"%s\"",
                   opts->module, opts->chroot_dir, user);
        }
        _pam_free_groups(group_list);

        return _PAM_CHROOT_OK;
      }
    } else {
      char* tmp = name;
      
      /* tack a NULL at the end of the name field */
      while(('\0' != *tmp) && !isspace(*tmp)) { tmp++; }
      *tmp = '\0';

      if (1 == name_is_group) {
        for (i = 0; NULL != group_list[i]; i++) {
          if (0 == (err = strcmp(group_list[i], name))) { break; }
        }
      } else {
        err = strcmp(user, name);
      }

      if (0 == err) {
        fclose(conf);

        opts->chroot_dir = _pam_expand_chroot_dir(mark, user, group, NULL,
                                                  NULL, opts);
        if (NULL == opts->chroot_dir) {
          _pam_log(LOG_ERR, "%s: unable to expand chroot_dir", opts->module);
          return _PAM_CHROOT_SYSERR;
        } 
        if (opts->flags & _PAM_OPTS_DEBUG) {
          _pam_log(LOG_NOTICE, "%s: found chroot_dir \"%s\" for user \"%s\"",
                   opts->module, opts->chroot_dir, user);
        }
        _pam_free_groups(group_list);
        return _PAM_CHROOT_OK;
      }
    }
    if (opts->flags & _PAM_OPTS_DEBUG) {
      _pam_log(LOG_NOTICE, "%s: \"%s\" does not match \"%s\"", opts->module,
               user, conf_line);
    }
  } /* end while(fgets(conf_line, LINELEN, conf)) */

  if (opts->flags & _PAM_OPTS_DEBUG) {
    _pam_log(LOG_NOTICE,
             "%s: no match found for user \"%s\" in conf file \"%s\"",
             opts->module, user, opts->conf);
  }
  fclose(conf);
  _pam_free_groups(group_list);
  opts->chroot_dir = NULL;
  return _PAM_CHROOT_USERNOTFOUND;
}

/* This is the workhorse function.  All of the pam_sm_* functions should
 *  initialize a _pam_opts struct with the command line args and flags,
 *  then pass it to this function */
int _pam_do_chroot(pam_handle_t *pamh, _opts *opts) {
  int err,debug;
  char *name;
  char const *user;

  name = NULL;
  debug = opts->flags & _PAM_OPTS_DEBUG;

  err = pam_get_user(pamh, &user, NULL);
  if (PAM_CONV_AGAIN == err) {
    _pam_log(LOG_NOTICE, "%s: retry username lookup later", opts->module);
    return _PAM_CHROOT_INCOMPLETE;
  } else if (PAM_SUCCESS != err) {
    _pam_log(LOG_ERR, "%s: can't get username", opts->module);
    return _PAM_CHROOT_SYSERR;
  }

  if (opts->chroot_dir) { /* overrides the conf file */
    if (debug) {
      _pam_log(LOG_NOTICE, "%s: chrootdir (%s) specified, ignoring conf file",
               opts->module, opts->chroot_dir);
    }
    err = _PAM_CHROOT_OK;
  } else {
    if (debug) {
      _pam_log(LOG_NOTICE, "%s: reading config file (%s)", opts->module,
               opts->conf);
    }
    err = _pam_get_chrootdir(user, opts);
  }

  if (_PAM_CHROOT_OK == err) {
    if (debug) {
      _pam_log(LOG_NOTICE, "%s: preparing to chroot()", opts->module);
    }

    if (NULL == opts->chroot_dir) {
      /* This is a state that I should never see.  If the user wasn't in
       * the conf file, then USERNOTFOUND should have been returned. */
      _pam_log(LOG_ERR, "%s: no chroot_dir set for \"%s\"", opts->module,
               user);
      return _PAM_CHROOT_INTERNALERR;
    }

    if (opts->flags & _PAM_OPTS_SECCHECKS) {
      if (0 != _pam_check_path_perms(opts->chroot_dir, opts)) {
        _pam_log(LOG_ERR, "%s: chroot_dir \"%s\" failed security check",
                 opts->module, opts->chroot_dir);
        return _PAM_CHROOT_SYSERR;
      }
    }

    if (opts->flags & _PAM_OPTS_NO_CHROOT) {
      if (debug) {
        _pam_log(LOG_NOTICE, "%s: no_chroot is set, skipping chroot(%s)",
                 opts->module, opts->chroot_dir);
      }
    } else if (chdir(opts->chroot_dir) != 0) {
      _pam_log(LOG_ERR, "%s: chdir(%s): %s", opts->module, opts->chroot_dir,
               strerror(errno));
      return _PAM_CHROOT_SYSERR;
    } else if (chroot(opts->chroot_dir) != 0) {
      _pam_log(LOG_ERR, "%s: chroot(%s): %s", opts->module, opts->chroot_dir,
               strerror(errno));
      return _PAM_CHROOT_SYSERR;
    } else {
      if (debug) {
        _pam_log(LOG_NOTICE, "%s: chroot(%s) ok", opts->module,
                 opts->chroot_dir);
      }
    }
    return _PAM_CHROOT_OK;
  } else if (_PAM_CHROOT_USERNOTFOUND == err) {
    if (debug) {
      _pam_log(LOG_NOTICE, "%s: no match for %s in %s", opts->module, user,
               opts->conf);
    }
    return _PAM_CHROOT_USERNOTFOUND;
  } else {
    _pam_log(LOG_ERR,
             "%s: error determining chrootdir: user=\"%s\", dir=\"%s\"",
             opts->module, user, opts->chroot_dir);
    return err;
  }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  int err;
  _opts opts;

  _pam_opts_init(&opts);
  _pam_opts_config(&opts, flags, argc, argv);
  opts.module = "auth";

  err = _pam_do_chroot(pamh, &opts);
  switch(err) {
    case _PAM_CHROOT_OK:
      if (opts.flags & _PAM_OPTS_DEBUG) {
        _pam_log(LOG_NOTICE, "%s: returning success", opts.module);
      }
      err = PAM_SUCCESS;
      break;

    case _PAM_CHROOT_USERNOTFOUND:
      if (opts.flags & _PAM_OPTS_DEBUG) {
        _pam_log(LOG_NOTICE, "%s: unknown user", opts.module);
      }
      err = PAM_USER_UNKNOWN;
      break;

    case _PAM_CHROOT_INCOMPLETE:
      _pam_log(LOG_NOTICE, "%s: returning incomplete", opts.module);
      err = PAM_INCOMPLETE;
      break;

    case _PAM_CHROOT_INTERNALERR:
      _pam_log(LOG_ERR, "%s: internal error encountered", opts.module);
      err = PAM_AUTH_ERR;
      break;

    default:
      if (opts.flags & _PAM_OPTS_DEBUG) {
        _pam_log(LOG_NOTICE, "%s: returning failure", opts.module);
      }
      err = PAM_AUTH_ERR;
      break;
  }
  _pam_opts_free(&opts);
  return err;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const
                              char **argv) {
  _pam_log(LOG_ERR, "not a credentialator");
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const
                                char **argv) {
  int err;
  _opts opts;

  _pam_opts_init(&opts);
  _pam_opts_config(&opts, flags, argc, argv);
  opts.module = "account";

  err = _pam_do_chroot(pamh, &opts);
  switch(err) {
    case _PAM_CHROOT_OK:
      if (opts.flags & _PAM_OPTS_DEBUG) {
        _pam_log(LOG_NOTICE, "%s: returning success", opts.module);
      }
      err = PAM_SUCCESS;
      break;

    case _PAM_CHROOT_USERNOTFOUND:
      if (opts.flags & _PAM_OPTS_DEBUG) {
        _pam_log(LOG_NOTICE, "%s: unknown user", opts.module);
      }
      err = PAM_USER_UNKNOWN;
      break;

    case _PAM_CHROOT_INCOMPLETE:
      _pam_log(LOG_NOTICE, "%s: returning incomplete", opts.module);
      err = PAM_INCOMPLETE;
      break;

    case _PAM_CHROOT_INTERNALERR:
      _pam_log(LOG_ERR, "%s: internal error encountered", opts.module);
      err = PAM_AUTH_ERR;
      break;

    default:
      if (opts.flags & _PAM_OPTS_DEBUG) {
        _pam_log(LOG_NOTICE, "%s: returning failure", opts.module);
      }
      err = PAM_AUTH_ERR;
      break;
  }
  _pam_opts_free(&opts);
  return err;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  int err;
  _opts opts;

  _pam_opts_init(&opts);
  _pam_opts_config(&opts, flags, argc, argv);
  opts.module = "session";

  err = _pam_do_chroot(pamh, &opts);
  switch(err) {
    case _PAM_CHROOT_OK:
      if (opts.flags & _PAM_OPTS_DEBUG) {
        _pam_log(LOG_NOTICE, "%s: returning success", opts.module);
      }
      err = PAM_SUCCESS;
      break;

    case _PAM_CHROOT_USERNOTFOUND:
      if (opts.flags & _PAM_OPTS_NOTFOUNDFAILS) {
        if (opts.flags & _PAM_OPTS_DEBUG) {
          _pam_log(LOG_NOTICE,
                   "%s: notfound=failure is set, returning failure",
                   opts.module);
        }
        err = PAM_SESSION_ERR;
      } else {
        err = PAM_SUCCESS;
      }
      break;

    case _PAM_CHROOT_INCOMPLETE:
      _pam_log(LOG_NOTICE, "%s: returning incomplete", opts.module);
      err = PAM_INCOMPLETE;
      break;

    case _PAM_CHROOT_INTERNALERR:
      _pam_log(LOG_ERR, "%s: internal error encountered", opts.module);
      err = PAM_SESSION_ERR;
      break;

    default:
      if (opts.flags * _PAM_OPTS_DEBUG) {
        _pam_log(LOG_NOTICE, "%s: returning failure", opts.module);
      }
      err = PAM_SESSION_ERR;
      break;
  }
  _pam_opts_free(&opts);
  return err;
}


PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const
                                char **argv) {
  _pam_log(LOG_ERR, "password management group is unsupported");
  return PAM_SERVICE_ERR;
}


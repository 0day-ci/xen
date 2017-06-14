/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libxl.h>
#include <libxl_utils.h>

#include "xl.h"
#include "xl_utils.h"

int with_lock(uint32_t domid, domain_fn fn, void *arg)
{
    char filename[sizeof(XL_DOMAIN_LOCK_FILE_FMT)+15];
    int fd_lock = -1;
    int rc;

    snprintf(filename, sizeof(filename), XL_DOMAIN_LOCK_FILE_FMT, domid);

    rc = acquire_lock(filename, &fd_lock);
    if (rc) goto out;

    rc = fn(arg);

    release_lock(filename, &fd_lock);

out:
    return rc;
}

void dolog(const char *file, int line, const char *func, char *fmt, ...)
{
    va_list ap;
    char *s = NULL;
    int rc;

    va_start(ap, fmt);
    rc = vasprintf(&s, fmt, ap);
    va_end(ap);
    if (rc >= 0)
        /* we ignore write errors since we have no way to report them;
         * the alternative would be to abort the whole program */
        libxl_write_exactly(NULL, logfile, s, rc, NULL, NULL);
    free(s);
}

void xvasprintf(char **strp, const char *fmt, va_list ap)
{
    int r = vasprintf(strp, fmt, ap);
    if (r == -1) {
        perror("asprintf failed");
        exit(EXIT_FAILURE);
    }
}

void xasprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    xvasprintf(strp, fmt, ap);
    va_end(ap);
}

void *xmalloc(size_t sz)
{
    void *r;
    r = malloc(sz);
    if (!r) {
        fprintf(stderr,"xl: Unable to malloc %lu bytes.\n",
                (unsigned long)sz);
        exit(-ERROR_FAIL);
    }
    return r;
}

void *xcalloc(size_t n, size_t sz)
{
    void *r = calloc(n, sz);
    if (!r) {
        fprintf(stderr,"xl: Unable to calloc %zu bytes.\n", sz*n);
        exit(-ERROR_FAIL);
    }
    return r;
}

void *xrealloc(void *ptr, size_t sz)
{
    void *r;
    if (!sz) {
        free(ptr);
        return 0;
    }
    /* realloc(non-0, 0) has a useless return value;
     * but xrealloc(anything, 0) is like free
     */
    r = realloc(ptr, sz);
    if (!r) {
        fprintf(stderr,"xl: Unable to realloc to %lu bytes.\n",
                (unsigned long)sz);
        exit(-ERROR_FAIL);
    }
    return r;
}

char *xstrdup(const char *x)
{
    char *r;
    r = strdup(x);
    if (!r) {
        fprintf(stderr, "xl: Unable to strdup a string of length %zu.\n",
                strlen(x));
        exit(-ERROR_FAIL);
    }
    return r;
}

void flush_stream(FILE *fh)
{
    const char *fh_name =
        fh == stdout ? "stdout" :
        fh == stderr ? "stderr" :
        (abort(), (const char*)0);

    if (ferror(fh) || fflush(fh)) {
        perror(fh_name);
        exit(EXIT_FAILURE);
    }
}

uint32_t find_domain(const char *p)
{
    uint32_t domid;
    int rc;

    rc = libxl_domain_qualifier_to_domid(ctx, p, &domid);
    if (rc) {
        fprintf(stderr, "%s is an invalid domain identifier (rc=%d)\n", p, rc);
        exit(EXIT_FAILURE);
    }
    common_domname = libxl_domid_to_name(ctx, domid);
    return domid;
}

/*
 * Callers should use SWITCH_FOREACH_OPT in preference to calling this
 * directly.
 */
int def_getopt(int argc, char * const argv[],
                const char *optstring,
                const struct option *longopts,
                const char* helpstr, int reqargs)
{
    int opt;
    const struct option def_options[] = {
        COMMON_LONG_OPTS
    };

    if (!longopts)
        longopts = def_options;

    opterr = 0;
    while ((opt = getopt_long(argc, argv, optstring, longopts, NULL)) == '?') {
        if (optopt == 'h') {
            help(helpstr);
            exit(0);
        }
        fprintf(stderr, "option `%c' not supported.\n", optopt);
        exit(2);
    }
    if (opt == 'h') {
        help(helpstr);
        exit(0);
    }
    if (opt != -1)
        return opt;

    if (argc - optind <= reqargs - 1) {
        fprintf(stderr, "'xl %s' requires at least %d argument%s.\n\n",
                helpstr, reqargs, reqargs > 1 ? "s" : "");
        help(helpstr);
        exit(2);
    }
    return -1;
}

void string_realloc_append(char **accumulate, const char *more)
{
    /* Appends more to accumulate.  Accumulate is either NULL, or
     * points (always) to a malloc'd nul-terminated string. */

    size_t oldlen = *accumulate ? strlen(*accumulate) : 0;
    size_t morelen = strlen(more) + 1/*nul*/;
    if (oldlen > SSIZE_MAX || morelen > SSIZE_MAX - oldlen) {
        fprintf(stderr,"Additional config data far too large\n");
        exit(-ERROR_FAIL);
    }

    *accumulate = xrealloc(*accumulate, oldlen + morelen);
    memcpy(*accumulate + oldlen, more, morelen);
}

void print_bitmap(uint8_t *map, int maplen, FILE *stream)
{
    int i;
    uint8_t pmap = 0, bitmask = 0;
    int firstset = 0, state = 0;

    for (i = 0; i < maplen; i++) {
        if (i % 8 == 0) {
            pmap = *map++;
            bitmask = 1;
        } else bitmask <<= 1;

        switch (state) {
        case 0:
        case 2:
            if ((pmap & bitmask) != 0) {
                firstset = i;
                state++;
            }
            continue;
        case 1:
        case 3:
            if ((pmap & bitmask) == 0) {
                fprintf(stream, "%s%d", state > 1 ? "," : "", firstset);
                if (i - 1 > firstset)
                    fprintf(stream, "-%d", i - 1);
                state = 2;
            }
            continue;
        }
    }
    switch (state) {
        case 0:
            fprintf(stream, "none");
            break;
        case 2:
            break;
        case 1:
            if (firstset == 0) {
                fprintf(stream, "all");
                break;
            }
        case 3:
            fprintf(stream, "%s%d", state > 1 ? "," : "", firstset);
            if (i - 1 > firstset)
                fprintf(stream, "-%d", i - 1);
            break;
    }
}

int do_daemonize(char *name, const char *pidfile)
{
    char *fullname;
    pid_t child1;
    int nullfd, ret = 0;

    child1 = xl_fork(child_waitdaemon, "domain monitoring daemonizing child");
    if (child1) {
        ret = child_report(child_waitdaemon);
        if (ret) goto out;
        ret = 1;
        goto out;
    }

    postfork();

    ret = libxl_create_logfile(ctx, name, &fullname);
    if (ret) {
        LOG("failed to open logfile %s: %s",fullname,strerror(errno));
        exit(-1);
    }

    CHK_SYSCALL(logfile = open(fullname, O_WRONLY|O_CREAT|O_APPEND, 0644));
    free(fullname);
    assert(logfile >= 3);

    CHK_SYSCALL(nullfd = open("/dev/null", O_RDONLY));
    assert(nullfd >= 3);

    dup2(nullfd, 0);
    dup2(logfile, 1);
    dup2(logfile, 2);

    close(nullfd);

    CHK_SYSCALL(daemon(0, 1));

    if (pidfile) {
        int fd = open(pidfile, O_RDWR | O_CREAT, S_IRUSR|S_IWUSR);
        char *pid = NULL;

        if (fd == -1) {
            perror("Unable to open pidfile");
            exit(1);
        }

        if (asprintf(&pid, "%ld\n", (long)getpid()) == -1) {
            perror("Formatting pid");
            exit(1);
        }

        if (write(fd, pid, strlen(pid)) < 0) {
            perror("Writing pid");
            exit(1);
        }

        if (close(fd) < 0) {
            perror("Closing pidfile");
            exit(1);
        }

        free(pid);
    }

out:
    return ret;
}

int acquire_lock(const char *lockfile, int *fd_lock)
{
    int rc;
    struct flock fl;

    /* lock already acquired */
    if (*fd_lock >= 0)
        return ERROR_INVAL;

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    *fd_lock = open(lockfile, O_WRONLY|O_CREAT, S_IWUSR);
    if (*fd_lock < 0) {
        fprintf(stderr, "cannot open the lockfile %s errno=%d\n",
                lockfile, errno);
        return ERROR_FAIL;
    }
    if (fcntl(*fd_lock, F_SETFD, FD_CLOEXEC) < 0) {
        close(*fd_lock);
        fprintf(stderr, "cannot set cloexec to lockfile %s errno=%d\n",
                lockfile, errno);
        return ERROR_FAIL;
    }
get_lock:
    rc = fcntl(*fd_lock, F_SETLKW, &fl);
    if (rc < 0 && errno == EINTR)
        goto get_lock;
    if (rc < 0) {
        fprintf(stderr, "cannot acquire lock %s errno=%d\n",
                lockfile, errno);
        rc = ERROR_FAIL;
    } else
        rc = 0;
    return rc;
}

int release_lock(const char *lockfile, int *fd_lock)
{
    int rc;
    struct flock fl;

    /* lock not acquired */
    if (*fd_lock < 0)
        return ERROR_INVAL;

release_lock:
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;

    rc = fcntl(*fd_lock, F_SETLKW, &fl);
    if (rc < 0 && errno == EINTR)
        goto release_lock;
    if (rc < 0) {
        fprintf(stderr, "cannot release lock %s, errno=%d\n",
                lockfile, errno);
        rc = ERROR_FAIL;
    } else
        rc = 0;
    close(*fd_lock);
    *fd_lock = -1;

    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

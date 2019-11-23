/* set user and group id and exec */

#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

static char *argv0;

static void usage(int exitcode)
{
	printf("Usage: %s user-spec new-root command [args]\n", argv0);
	exit(exitcode);
}

static void do_chroot(const char *root)
{
	if (root[0] == '\0' || (root[0] == '/' && root[1] == '\0')) {
		return;
	}
	if (chroot(root))
		err(1, "chroot(%s)", root);
}

static void parse_passwd(const char *path, int fields, void (*handler)(int, const char*, void*), void *cookie)
{
	int fd, findex, fill, bindex;
	char buf[128], accu[256];
	ssize_t rcount;
	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "open(%s)", path);
	findex = fill = 0;
	for (;;) {
		rcount = read(fd, buf, 128);
		if (rcount == (ssize_t)-1)
			err(1, "read(%s)", path);
		if (!rcount) {
			if (findex || fill) {
				if (findex + 1 == fields) {
					accu[fill] = '\0';
					handler(findex, accu, cookie);
				}
				else
					handler(findex, NULL, cookie);
			}
			break;
		}
		for (bindex = 0; bindex < (int)rcount; ++bindex) {
			switch (buf[bindex]) {
				case ':':
					accu[fill] = '\0';
					handler(findex, accu, cookie);
					fill = 0;
					++findex;
					break;
				case '\n':
					if (findex + 1 == fields) {
						accu[fill] = '\0';
						handler(findex, accu, cookie);
					}
					else
						handler(findex, NULL, cookie);
					fill = findex = 0;
					break;
				default:
					if (fill < 255)
						accu[fill++] = buf[bindex];
					break;
			}
		}
	}
	if (close(fd))
		err(1, "close(%s)", path);
}

enum match_state
{
	M_ST_UNKNOWN,
	M_ST_MATCHED,
	M_ST_UNMATCHED,
	M_ST_DONE
};

enum passwd_field
{
	PW_F_LOGIN,
	PW_F_PASSWORD,
	PW_F_UID,
	PW_F_GID,
	PW_F_COMMENT,
	PW_F_HOME,
	PW_F_SHELL
};

static struct passwd the_one_true_passwd = {};

struct passwd_query
{
	const char *name;
	uid_t uid;
	enum match_state state;
};

static void passwd_handler(int findex, const char *field, void *cookie)
{
	/* we need pw_uid, pw_gid, pw_dir, pw_name */
	struct passwd_query *query;
	char *int_end;
	query = (struct passwd_query*)cookie;
	switch (query->state) {
		case M_ST_UNKNOWN:
			break;
		case M_ST_MATCHED:
			if (findex)
				break;
			query->state = M_ST_DONE;
			return;
		case M_ST_UNMATCHED:
			if (!findex)
				query->state = M_ST_UNKNOWN;
			break;
		case M_ST_DONE:
			return;
	}
	if (!field)
		query->state = M_ST_UNMATCHED;
	if (query->state == M_ST_UNMATCHED)
		return;
	switch (findex) {
		case PW_F_LOGIN:
			if (query->name) {
				if (strcmp(field, query->name)) {
					query->state = M_ST_UNMATCHED;
					break;
				}
				query->state = M_ST_MATCHED;
			}
			if (!the_one_true_passwd.pw_name) {
				the_one_true_passwd.pw_name = (char*)malloc(256);
				if (!the_one_true_passwd.pw_name)
					err(1, "malloc");
			}
			strcpy(the_one_true_passwd.pw_name, field);
			break;
		case PW_F_PASSWORD:
		case PW_F_COMMENT:
		case PW_F_SHELL:
			break;
		case PW_F_UID:
			if (query->state == M_ST_UNMATCHED)
				break;
			the_one_true_passwd.pw_uid = (uid_t)strtol(field, &int_end, 10);
			if (*int_end) {
				query->state = M_ST_UNMATCHED;
				break;
			}
			if (!query->name)
				query->state = the_one_true_passwd.pw_uid == query->uid ? M_ST_MATCHED : M_ST_UNMATCHED;
			break;
		case PW_F_GID:
			if (query->state != M_ST_MATCHED)
				break;
			the_one_true_passwd.pw_gid = (gid_t)strtol(field, &int_end, 10);
			if (*int_end)
				query->state = M_ST_UNMATCHED;
			break;
		case PW_F_HOME:
			if (query->state != M_ST_MATCHED)
				break;
			if (!the_one_true_passwd.pw_dir) {
				the_one_true_passwd.pw_dir = (char*)malloc(256);
				if (!the_one_true_passwd.pw_dir)
					err(1, "malloc");
			}
			strcpy(the_one_true_passwd.pw_dir, field);
			break;
	}
}

struct passwd *fake_getpwnam(const char *name)
{
	struct passwd_query query;
	query.name = name;
	query.state = M_ST_UNKNOWN;
	parse_passwd("/etc/passwd", 7, passwd_handler, &query);
	switch (query.state) {
		case M_ST_MATCHED:
		case M_ST_DONE:
			return &the_one_true_passwd;
		default:
			errno = ENOENT;
			return NULL;
	}
}

struct passwd *fake_getpwuid(uid_t uid)
{
	struct passwd_query query;
	query.name = NULL;
	query.uid = uid;
	query.state = M_ST_UNKNOWN;
	parse_passwd("/etc/passwd", 7, passwd_handler, &query);
	switch (query.state) {
		case M_ST_MATCHED:
		case M_ST_DONE:
			return &the_one_true_passwd;
		default:
			errno = ENOENT;
			return NULL;
	}
}

enum group_field
{
	GR_F_NAME,
	GR_F_PASSWORD,
	GR_F_GID,
	GR_F_MEMBERS
};

static struct group the_one_true_group = {};

struct group_query
{
	const char *name;
	enum match_state state;
};

static void group_handler(int findex, const char *field, void *cookie)
{
	/* we only need gr_gid */
	struct group_query *query;
	char *int_end;
	query = (struct group_query*)cookie;
	switch (query->state) {
		case M_ST_UNKNOWN:
			break;
		case M_ST_MATCHED:
			if (findex)
				break;
			query->state = M_ST_DONE;
			return;
		case M_ST_UNMATCHED:
			if (!findex)
				query->state = M_ST_UNKNOWN;
			break;
		case M_ST_DONE:
			return;
	}
	if (!field)
		query->state = M_ST_UNMATCHED;
	if (query->state == M_ST_UNMATCHED)
		return;
	switch (findex) {
		case GR_F_NAME:
			query->state = strcmp(field, query->name) ? M_ST_UNMATCHED : M_ST_MATCHED;
			break;
		case GR_F_PASSWORD:
		case GR_F_MEMBERS:
			break;
		case GR_F_GID:
			if (query->state != M_ST_MATCHED)
				break;
			the_one_true_group.gr_gid = (gid_t)strtol(field, &int_end, 10);
			if (*int_end)
				query->state = M_ST_UNMATCHED;
			break;
	}
}

struct group *fake_getgrnam(const char *name)
{
	struct group_query query;
	query.name = name;
	query.state = M_ST_UNKNOWN;
	parse_passwd("/etc/group", 4, group_handler, &query);
	switch (query.state) {
		case M_ST_MATCHED:
		case M_ST_DONE:
			return &the_one_true_group;
		default:
			errno = ENOENT;
			return NULL;
	}
}

static int user_list_contains(const char *haystack, const char *needle, size_t needle_length)
{
	const char *pos;
	while (*haystack) {
		pos = strchr(haystack, ',');
		if (pos) {
			if (pos - haystack == needle_length && !memcmp(haystack, needle, needle_length))
				return 1;
			haystack = pos + 1;
		}
		else
			return !strcmp(haystack, needle);
	}
	return 0;
}

struct grouplist_query
{
	const char *user;
	size_t user_length;
	gid_t group;
	gid_t *groups;
	int ngroups_in, ngroups_out;
	gid_t in_group;
	int seen_group, line_valid, have_gid;
};

static void add_grouplist_gid(struct grouplist_query *query) {
	if (query->in_group == query->group)
		query->seen_group = 1;
	if (query->ngroups_out < query->ngroups_in)
		query->groups[query->ngroups_out++] = query->in_group;
}

static void grouplist_handler(int findex, const char *field, void *cookie)
{
	struct grouplist_query *query;
	char *int_end;
	query = (struct grouplist_query*)cookie;
	if (!findex) {
		if (query->line_valid && query->have_gid)
			add_grouplist_gid(query);
		query->line_valid = 1;
		query->have_gid = 0;
	}
	if (!field)
		query->line_valid = 0;
	if (!query->line_valid)
		return;
	switch (findex) {
		case GR_F_NAME:
		case GR_F_PASSWORD:
			break;
		case GR_F_GID:
			query->in_group = (gid_t)strtol(field, &int_end, 10);
			if (*int_end)
				query->line_valid = 0;
			else
				query->have_gid = 1;
			break;
		case GR_F_MEMBERS:
			if (!user_list_contains(field, query->user, query->user_length))
				query->line_valid = 0;
			break;
	}
}

static int fake_getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups)
{
	struct grouplist_query query;
	query.user = user;
	query.user_length = strlen(user);
	query.group = group;
	query.groups = groups;
	query.ngroups_in = *ngroups;
	query.ngroups_out = 0;
	query.seen_group = 0;
	query.line_valid = 1;
	query.have_gid = 0;
	parse_passwd("/etc/group", 4, grouplist_handler, &query);
	if (query.line_valid && query.have_gid)
		add_grouplist_gid(&query);
	if (!query.seen_group) {
		query.in_group = group;
		add_grouplist_gid(&query);
	}
	*ngroups = query.ngroups_out;
	if (query.ngroups_out > query.ngroups_in)
		return -1;
	return query.ngroups_out;
}

int main(int argc, char *argv[])
{
	char *user, *group, **cmdargv;
	char *end;

	uid_t uid = getuid();
	gid_t gid = getgid();

	argv0 = argv[0];
	if (argc < 4)
		usage(0);

	user = argv[1];
	group = strchr(user, ':');
	if (group)
		*group++ = '\0';

	cmdargv = &argv[3];

	struct passwd *pw = NULL;
	if (user[0] != '\0') {
		uid_t nuid = strtol(user, &end, 10);
		if (*end == '\0')
			uid = nuid;
		else {
			pw = fake_getpwnam(user);
			if (pw == NULL)
				err(1, "getpwnam(%s)", user);
		}
	}
	if (pw == NULL) {
		pw = fake_getpwuid(uid);
	}
	if (pw != NULL) {
		uid = pw->pw_uid;
		gid = pw->pw_gid;
	}

	setenv("HOME", pw != NULL ? pw->pw_dir : "/", 1);

	if (group && group[0] != '\0') {
		/* group was specified, ignore grouplist for setgroups later */
		pw = NULL;

		gid_t ngid = strtol(group, &end, 10);
		if (*end == '\0')
			gid = ngid;
		else {
			struct group *gr = fake_getgrnam(group);
			if (gr == NULL)
				err(1, "getgrnam(%s)", group);
			gid = gr->gr_gid;
		}
	}

	if (pw == NULL) {
		do_chroot(argv[2]);
		if (setgroups(1, &gid) < 0)
			err(1, "setgroups(%i)", gid);
	} else {
		int ngroups = 0;
		gid_t *glist = NULL;

		while (1) {
			int r = fake_getgrouplist(pw->pw_name, gid, glist, &ngroups);

			if (r >= 0) {
				do_chroot(argv[2]);
				if (setgroups(ngroups, glist) < 0)
					err(1, "setgroups");
				break;
			}

			glist = realloc(glist, ngroups * sizeof(gid_t));
			if (glist == NULL)
				err(1, "malloc");
		}
	}

	if (setgid(gid) < 0)
		err(1, "setgid(%i)", gid);

	if (setuid(uid) < 0)
		err(1, "setuid(%i)", uid);

	execvp(cmdargv[0], cmdargv);
	err(1, "%s", cmdargv[0]);

	return 1;
}

/* -*- buffer-read-only: t -*- vi: set ro: */
/* DO NOT EDIT! GENERATED AUTOMATICALLY! */
#line 1
/* Test of <stat-time.h>.
   Copyright (C) 2007-2008 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by James Youngman <jay@gnu.org>, 2007.  */

#include <config.h>

#include "stat-time.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define ASSERT(expr) \
  do									     \
    {									     \
      if (!(expr))							     \
        {								     \
          fprintf (stderr, "%s:%d: assertion failed\n", __FILE__, __LINE__); \
          fflush (stderr);						     \
          abort ();							     \
        }								     \
    }									     \
  while (0)

enum { NFILES = 4 };

static void
force_unlink (const char *filename)
{
  /* This chmod is necessary on mingw, where unlink() of a read-only file
     fails with EPERM.  */
  chmod (filename, 0600);
  unlink (filename);
}

static void
cleanup (int sig)
{
  /* Remove temporary files.  */
  force_unlink ("t-stt-stamp1");
  force_unlink ("t-stt-testfile");
  force_unlink ("t-stt-stamp2");
  force_unlink ("t-stt-renamed");
  force_unlink ("t-stt-stamp3");

  if (sig != 0)
    _exit (1);
}

static int
open_file (const char *filename, int flags)
{
  int fd = open (filename, flags | O_WRONLY, 0500);
  if (fd >= 0)
    {
      close (fd);
      return 1;
    }
  else
    {
      return 0;
    }
}

static void
create_file (const char *filename)
{
  ASSERT (open_file (filename, O_CREAT | O_EXCL));
}

static void
do_stat (const char *filename, struct stat *p)
{
  ASSERT (stat (filename, p) == 0);
}

static void
prepare_test (struct stat *statinfo, struct timespec *modtimes)
{
  int i;

  create_file ("t-stt-stamp1");
  sleep (2);
  create_file ("t-stt-testfile");
  sleep (2);
  create_file ("t-stt-stamp2");
  sleep (2);
  ASSERT (chmod ("t-stt-testfile", 0400) == 0);
  sleep (2);
  create_file ("t-stt-stamp3");

  do_stat ("t-stt-stamp1",  &statinfo[0]);
  do_stat ("t-stt-testfile", &statinfo[1]);
  do_stat ("t-stt-stamp2",  &statinfo[2]);
  do_stat ("t-stt-stamp3",  &statinfo[3]);

  /* Now use our access functions. */
  for (i = 0; i < NFILES; ++i)
    {
      modtimes[i] = get_stat_mtime (&statinfo[i]);
    }
}

static void
test_mtime (const struct stat *statinfo, struct timespec *modtimes)
{
  int i;

  /* Use the struct stat fields directly. */
  ASSERT (statinfo[0].st_mtime < statinfo[2].st_mtime); /* mtime(stamp1) < mtime(stamp2) */
  ASSERT (statinfo[2].st_mtime < statinfo[3].st_mtime); /* mtime(stamp2) < mtime(stamp3) */

  /* Now check the result of the access functions. */
  ASSERT (modtimes[0].tv_sec < modtimes[2].tv_sec); /* mtime(stamp1) < mtime(stamp2) */
  ASSERT (modtimes[2].tv_sec < modtimes[3].tv_sec); /* mtime(stamp2) < mtime(stamp3) */

  /* verify equivalence */
  for (i = 0; i < NFILES; ++i)
    {
      struct timespec ts;
      ts = get_stat_mtime (&statinfo[i]);
      ASSERT (ts.tv_sec == statinfo[i].st_mtime);
    }
}

static void
test_ctime (const struct stat *statinfo)
{
  ASSERT (statinfo[2].st_mtime < statinfo[1].st_ctime); /* mtime(stamp2) < ctime(renamed) */

  ASSERT (statinfo[2].st_mtime < statinfo[1].st_ctime); /* mtime(stamp2) < ctime(renamed) */
}

static void
test_birthtime (const struct stat *statinfo,
		const struct timespec *modtimes,
		struct timespec *birthtimes)
{
  int i;

  /* Collect the birth times.. */
  for (i = 0; i < NFILES; ++i)
    {
      birthtimes[i] = get_stat_birthtime (&statinfo[i]);
      if (birthtimes[i].tv_nsec < 0)
	return;
    }

  ASSERT (modtimes[0].tv_sec < birthtimes[1].tv_sec); /* mtime(stamp1) < birthtime(renamed) */
  ASSERT (birthtimes[1].tv_sec < modtimes[2].tv_sec); /* birthtime(renamed) < mtime(stamp2) */
}

int
main ()
{
  struct stat statinfo[NFILES];
  struct timespec modtimes[NFILES];
  struct timespec birthtimes[NFILES];

#ifdef SIGHUP
  signal (SIGHUP, cleanup);
#endif
#ifdef SIGINT
  signal (SIGINT, cleanup);
#endif
#ifdef SIGQUIT
  signal (SIGQUIT, cleanup);
#endif
#ifdef SIGTERM
  signal (SIGTERM, cleanup);
#endif

  cleanup (0);
  prepare_test (statinfo, modtimes);
  test_mtime (statinfo, modtimes);
  /* Skip the ctime tests on native Windows platforms, because there st_ctime
     is either the same as st_mtime (plus or minus an offset) or set to the
     file _creation_ time, and is not influenced by rename or chmod.  */
#if !((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
  test_ctime (statinfo);
#endif
  test_birthtime (statinfo, modtimes, birthtimes);

  cleanup (0);
  return 0;
}

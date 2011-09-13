/* cp.c  -- file copying (main routines)

   Copyright 2010 United States Government National Aeronautics and
   Space Administration (NASA).  No copyright is claimed in the United
   States under Title 17, U.S. Code.  All Other Rights Reserved.

   Copyright (C) 89, 90, 91, 1995-2009 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License Version 3 with
   Additional Terms below (per Section 7 of GPL V3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Torbjorn Granlund, David MacKenzie, and Jim Meyering.
   High performance multi-threaded modifications by Paul Kolano.  */

/* Additional Terms per Section 7 of GNU General Public License Version 3

1.  DISCLAIMER OF WARRANTIES AND LIABILITIES; WAIVER AND INDEMNIFICATION

    No Warranty: NASA PROVIDES THE COVERED WORKS "AS IS" WITHOUT ANY
    WARRANTY OF ANY KIND, EITHER EXPRESSED, IMPLIED, OR STATUTORY,
    INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY THAT THE COVERED WORKS
    WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR FREEDOM FROM
    INFRINGEMENT, ANY WARRANTY THAT THE COVERED WORKS WILL BE ERROR
    FREE, OR ANY WARRANTY THAT DOCUMENTATION, IF PROVIDED, WILL CONFORM
    TO THE COVERED WORKS. THIS AGREEMENT DOES NOT, IN ANY MANNER,
    CONSTITUTE AN ENDORSEMENT BY NASA OR ANY OTHER RECIPIENT OF ANY
    RESULTS, RESULTING DESIGNS, HARDWARE, SOFTWARE PRODUCTS OR ANY OTHER
    APPLICATIONS RESULTING FROM USE OF THE COVERED WORKS.  FURTHER, NASA
    DISCLAIMS ALL WARRANTIES AND LIABILITIES REGARDING THIRD-PARTY
    SOFTWARE, IF PRESENT IN THE ORIGINAL SOFTWARE, AND DISTRIBUTES IT
    "AS IS."

    Waiver and Indemnity: YOU AGREE TO WAIVE ANY AND ALL CLAIMS
    AGAINST THE UNITED STATES GOVERNMENT, ITS CONTRACTORS AND
    SUBCONTRACTORS, AS WELL AS ANY OTHER RECIPIENT.  IF YOUR USE OF THE
    COVERED WORKS RESULTS IN ANY LIABILITIES, DEMANDS, DAMAGES, EXPENSES
    OR LOSSES ARISING FROM SUCH USE, INCLUDING ANY DAMAGES FROM PRODUCTS
    BASED ON, OR RESULTING FROM, YOUR USE OF THE COVERED WORKS, YOU
    SHALL INDEMNIFY AND HOLD HARMLESS THE UNITED STATES GOVERNMENT, ITS
    CONTRACTORS AND SUBCONTRACTORS, AS WELL AS ANY OTHER RECIPIENT, TO
    THE EXTENT PERMITTED BY LAW.  YOUR SOLE REMEDY FOR ANY SUCH MATTER
    SHALL BE THE IMMEDIATE, UNILATERAL TERMINATION OF THIS AGREEMENT.

2.  You must ensure that the following copyright notice appears
    prominently in the covered works:

        Copyright 2010 United States Government National Aeronautics and
        Space Administration (NASA).  No copyright is claimed in the United
        States under Title 17, U.S. Code.  All Other Rights Reserved.

3.  You must characterize Your alteration of the covered works as a
    Modification or Contribution and must identify Yourself as the
    originator of Your Modification or Contribution in a manner that
    reasonably allows subsequent Recipients to identify the originator
    of the Modification or Contribution.  In fulfillment of these
    requirements, You must include a file (e.g., a change log file) that
    describes the alterations made and the date of the alterations,
    identifies You as originator of the alterations, and consents to
    characterization of the alterations as a Modification or
    Contribution, for example, by including a statement that the
    Modification or Contribution is derived, directly or indirectly,
    from covered work provided by NASA. Once consent is granted, it may
    not thereafter be revoked.

4.  You may not make any representation in the covered works or in any
    promotional, advertising or other material that may be construed as
    an endorsement by NASA or by any other Recipient of any product or
    service provided by You, or that may seek to obtain commercial
    advantage of NASA's or any other Recipient's participation in this
    License.
*/
#undef HAVE_LIBGNUTLS
#include <config.h>
#include <stdio.h>
#include <sys/types.h>
#include <getopt.h>
#include <selinux/selinux.h>

#include "system.h"
#include "argmatch.h"
#include "backupfile.h"
#include "copy.h"
#include "cp-hash.h"
#include "error.h"
#include "filenamecat.h"
#include "ignore-value.h"
// PZK >
#include "mcore.h"
#include "mkancesdirs.h"
#include "savewd.h"
#include <ctype.h>

#if HAVE_LIBGCRYPT
# include <gcrypt.h>
# ifdef _OPENMP
#  include <pthread.h>
GCRY_THREAD_OPTION_PTHREAD_IMPL;
# endif
#endif

#if HAVE_LIBMPI && defined(_OPENMP)
# include <mpi.h>
#endif

#include "quote.h"
#include "stat-time.h"
#include "utimens.h"
#include "acl.h"

#if ! HAVE_LCHOWN
# define lchown(name, uid, gid) chown (name, uid, gid)
#endif

#define ASSIGN_BASENAME_STRDUPA(Dest, File_name)	\
  do							\
    {							\
      char *tmp_abns_;					\
      ASSIGN_STRDUPA (tmp_abns_, (File_name));		\
      Dest = last_component (tmp_abns_);		\
      strip_trailing_slashes (Dest);			\
    }							\
  while (0)

/* The official name of this program (e.g., no `g' prefix).  */
// PZK >
#define PROGRAM_NAME "mcp 1.76.4"

#define AUTHORS \
  proper_name_utf8 ("Torbjorn Granlund", "Torbj\303\266rn Granlund"), \
  proper_name ("David MacKenzie"), \
  proper_name ("Jim Meyering"), \
  proper_name ("Paul Kolano")

#ifndef DEFAULT_BUFFER_SIZE
# define DEFAULT_BUFFER_SIZE 4
#endif
#ifndef DEFAULT_DIRECT_READ
# define DEFAULT_DIRECT_READ 0
#endif
#ifndef DEFAULT_DIRECT_WRITE
# define DEFAULT_DIRECT_WRITE 0
#endif
#ifndef DEFAULT_DOUBLE_BUFFER
# define DEFAULT_DOUBLE_BUFFER 0
#endif
#if !defined(DEFAULT_HASH_TYPE) && HAVE_LIBGCRYPT
# define DEFAULT_HASH_TYPE GCRY_MD_MD5
#endif
#ifndef DEFAULT_SPLIT_SIZE
# define DEFAULT_SPLIT_SIZE 0
#endif
#ifndef DEFAULT_THREADS
# define DEFAULT_THREADS 4
#endif
// < PZK

/* Used by do_copy, make_dir_parents_private, and re_protect
   to keep a list of leading directories whose protections
   need to be fixed after copying. */
struct dir_attr
{
  struct stat st;
  bool restore_mode;
  size_t slash_offset;
  struct dir_attr *next;
};

/* For long options that have no equivalent short option, use a
   non-character as a pseudo short option, starting with CHAR_MAX + 1.  */
enum
{
  COPY_CONTENTS_OPTION = CHAR_MAX + 1,
// PZK >
  BUFFER_SIZE_OPTION,
  DIRECT_READ_OPTION,
  DIRECT_WRITE_OPTION,
  DOUBLE_BUFFER_OPTION,
  LENGTH_OPTION,
  NO_DIRECT_READ_OPTION,
  NO_DIRECT_WRITE_OPTION,
  NO_DOUBLE_BUFFER_OPTION,
  OFFSET_OPTION,
  READ_STDIN_OPTION,
  SKIP_CHMOD_OPTION,
#ifdef POSIX_FADV_DONTNEED
  FADVISE_READ_OPTION,
  FADVISE_WRITE_OPTION,
#endif
#ifdef _OPENMP
  PRINT_STATS_OPTION,
  SPLIT_SIZE_OPTION,
  THREADS_OPTION,
#endif
#if HAVE_LIBLUSTREAPI
  PRINT_STRIPE_OPTION,
#endif
#if HAVE_LIBGCRYPT
  CHECK_TREE_OPTION,
  HASH_LEAF_SIZE_OPTION,
  HASH_TYPE_OPTION,
  PRINT_HASH_OPTION,
  STORE_HASH_OPTION,
#endif
#if HAVE_LIBMPI && defined(_OPENMP)
  MPI_OPTION,
#endif
  NO_PRESERVE_ATTRIBUTES_OPTION,
  PARENTS_OPTION,
  PRESERVE_ATTRIBUTES_OPTION,
  REFLINK_OPTION,
  SPARSE_OPTION,
  STRIP_TRAILING_SLASHES_OPTION,
  UNLINK_DEST_BEFORE_OPENING
};

/* True if the kernel is SELinux enabled.  */
static bool selinux_enabled;

/* If true, the command "cp x/e_file e_dir" uses "e_dir/x/e_file"
   as its destination instead of the usual "e_dir/e_file." */
static bool parents_option = false;

/* Remove any trailing slashes from each SOURCE argument.  */
static bool remove_trailing_slashes;

static char const *const sparse_type_string[] =
{
  "never", "auto", "always", NULL
};
static enum Sparse_type const sparse_type[] =
{
  SPARSE_NEVER, SPARSE_AUTO, SPARSE_ALWAYS
};
ARGMATCH_VERIFY (sparse_type_string, sparse_type);

static char const *const reflink_type_string[] =
{
  "auto", "always", NULL
};
static enum Reflink_type const reflink_type[] =
{
  REFLINK_AUTO, REFLINK_ALWAYS
};
ARGMATCH_VERIFY (reflink_type_string, reflink_type);

static struct option const long_opts[] =
{
// PZK >
  {"buffer-size", required_argument, NULL, BUFFER_SIZE_OPTION},
  {"direct-read", no_argument, NULL, DIRECT_READ_OPTION},
  {"direct-write", no_argument, NULL, DIRECT_WRITE_OPTION},
  {"double-buffer", no_argument, NULL, DOUBLE_BUFFER_OPTION},
  {"length", required_argument, NULL, LENGTH_OPTION},
  {"no-direct-read", no_argument, NULL, NO_DIRECT_READ_OPTION},
  {"no-direct-write", no_argument, NULL, NO_DIRECT_WRITE_OPTION},
  {"no-double-buffer", no_argument, NULL, NO_DOUBLE_BUFFER_OPTION},
  {"offset", required_argument, NULL, OFFSET_OPTION},
  {"read-stdin", no_argument, NULL, READ_STDIN_OPTION},
  {"skip-chmod", no_argument, NULL, SKIP_CHMOD_OPTION},
#ifdef POSIX_FADV_DONTNEED
  {"fadvise-read", no_argument, NULL, FADVISE_READ_OPTION},
  {"fadvise-write", no_argument, NULL, FADVISE_WRITE_OPTION},
#endif
#ifdef _OPENMP
  {"print-stats", no_argument, NULL, PRINT_STATS_OPTION},
  {"split-size", required_argument, NULL, SPLIT_SIZE_OPTION},
  {"threads", required_argument, NULL, THREADS_OPTION},
#endif
#if HAVE_LIBLUSTREAPI
  {"print-stripe", no_argument, NULL, PRINT_STRIPE_OPTION},
#endif
#if HAVE_LIBGCRYPT
  {"check-tree", no_argument, NULL, CHECK_TREE_OPTION},
  {"hash-leaf-size", required_argument, NULL, HASH_LEAF_SIZE_OPTION},
  {"hash-type", required_argument, NULL, HASH_TYPE_OPTION},
  {"print-hash", no_argument, NULL, PRINT_HASH_OPTION},
  {"store-hash", no_argument, NULL, STORE_HASH_OPTION},
#endif
#if HAVE_LIBMPI && defined(_OPENMP)
  {"mpi", no_argument, NULL, MPI_OPTION},
#endif
  {"archive", no_argument, NULL, 'a'},
  {"backup", optional_argument, NULL, 'b'},
  {"copy-contents", no_argument, NULL, COPY_CONTENTS_OPTION},
  {"dereference", no_argument, NULL, 'L'},
  {"force", no_argument, NULL, 'f'},
  {"interactive", no_argument, NULL, 'i'},
  {"link", no_argument, NULL, 'l'},
  {"no-clobber", no_argument, NULL, 'n'},
  {"no-dereference", no_argument, NULL, 'P'},
  {"no-preserve", required_argument, NULL, NO_PRESERVE_ATTRIBUTES_OPTION},
  {"no-target-directory", no_argument, NULL, 'T'},
  {"one-file-system", no_argument, NULL, 'x'},
  {"parents", no_argument, NULL, PARENTS_OPTION},
  {"path", no_argument, NULL, PARENTS_OPTION},   /* Deprecated.  */
  {"preserve", optional_argument, NULL, PRESERVE_ATTRIBUTES_OPTION},
  {"recursive", no_argument, NULL, 'R'},
  {"remove-destination", no_argument, NULL, UNLINK_DEST_BEFORE_OPENING},
  {"sparse", required_argument, NULL, SPARSE_OPTION},
  {"reflink", optional_argument, NULL, REFLINK_OPTION},
  {"strip-trailing-slashes", no_argument, NULL, STRIP_TRAILING_SLASHES_OPTION},
  {"suffix", required_argument, NULL, 'S'},
  {"symbolic-link", no_argument, NULL, 's'},
  {"target-directory", required_argument, NULL, 't'},
  {"update", no_argument, NULL, 'u'},
  {"verbose", no_argument, NULL, 'v'},
  {GETOPT_HELP_OPTION_DECL},
  {GETOPT_VERSION_OPTION_DECL},
  {NULL, 0, NULL, 0}
};

void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
             program_name);
  else
    {
      printf (_("\
Usage: %s [OPTION]... [-T] SOURCE DEST\n\
  or:  %s [OPTION]... SOURCE... DIRECTORY\n\
  or:  %s [OPTION]... -t DIRECTORY SOURCE...\n\
"),
              program_name, program_name, program_name);
      fputs (_("\
Copy SOURCE to DEST, or multiple SOURCE(s) to DIRECTORY.\n\
\n\
"), stdout);
// PZK >
      fputs (_("Mcp-specific options (defaults in brackets):\n"), stdout);
      fprintf (stdout, _("\
      --buffer-size=MBYTES     read/write buffer size [%d]\n"),
        DEFAULT_BUFFER_SIZE);
#if HAVE_LIBGCRYPT
      fputs (_("\
      --check-tree             print hash subtrees to pinpoint corruption\n\
"), stdout);
#endif
#if !DEFAULT_DIRECT_READ
      fputs (_("\
      --direct-read            enable use of direct I/O for reads\n\
"), stdout);
#endif
#if !DEFAULT_DIRECT_WRITE
      fputs (_("\
      --direct-write           enable use of direct I/O for writes\n\
"), stdout);
#endif
#if !DEFAULT_DOUBLE_BUFFER
      fputs (_("\
      --double-buffer          enable use of double buffering during file I/O\n\
"), stdout);
#endif
#ifdef POSIX_FADV_DONTNEED
      fputs (_("\
      --fadvise-read           enable use of posix_fadvise during reads\n\
      --fadvise-write          enable use of posix_fadvise during writes\n\
"), stdout);
#endif
#if HAVE_LIBGCRYPT
      fprintf (stdout, _("\
      --hash-leaf-size=KBYTES  granularity of hash tree [%d]\n\
      --hash-type=TYPE         hash type [%s], with TYPE one of:\n\
                                 "),
        DEFAULT_SPLIT_SIZE * 1024, gcry_md_algo_name(DEFAULT_HASH_TYPE));
      int n = 33;
      // 400 taken from libgcrypt benchmark code
      for (int i = 1; i < 400; i++) {
        if (gcry_md_test_algo(i)) continue;
        char *name = gcry_md_algo_name(i);
        if (n + strlen(name) > 78) {
            fputs (_("\n                                 "), stdout);
            n = 33;
        }
        n += strlen(name);
        while (*name) fputc(tolower(*name++), stdout);
        fputc(' ', stdout);
      }
      fputs(_("\n"), stdout);
#endif
      fputs (_("\
      --length=LEN             copy LEN bytes beginning at --offset\n\
                                 (or 0 if --offset not specified)\n\
"), stdout);
#if HAVE_LIBMPI && defined(_OPENMP)
      fputs (_("\
      --mpi                    enable use of MPI for multi-node copies\n\
"), stdout);
#endif
#if DEFAULT_DIRECT_READ
      fputs (_("\
      --no-direct-read         disable use of direct I/O for reads\n\
"), stdout);
#endif
#if DEFAULT_DIRECT_WRITE
      fputs (_("\
      --no-direct-write        disable use of direct I/O for writes\n\
"), stdout);
#endif
#if DEFAULT_DOUBLE_BUFFER
      fputs (_("\
      --no-double-buffer       disable use of double buffering during file I/O\n\
"), stdout);
#endif
      fputs (_("\
      --offset=POS             copy --length bytes beginning at POS\n\
                                 (or to end if --length not specified)\n\
"), stdout);
#if HAVE_LIBGCRYPT
      fputs (_("\
      --print-hash             print hash of each file to stdout similar to\n\
                                 md5sum, with sum of the src file computed,\n\
                                 but dst file name printed so that md5sum -c\n\
                                 can be used on the output to check that the\n\
                                 data written to disk was what was read\n\
"), stdout);
#endif
#ifdef _OPENMP
      fputs (_("\
      --print-stats            print performance per file to stderr\n\
"), stdout);
#endif
#if HAVE_LIBLUSTREAPI
      fputs (_("\
      --print-stripe           print striping changes to stderr\n\
"), stdout);
#endif
#ifdef _OPENMP
      fputs (_("\
      --read-stdin             perform a batch of operations read over stdin\n\
                                 in the form 'SRC DST RANGES' where SRC and DST\n\
                                 must be URI-escaped (RFC 3986) file names and\n\
                                 RANGES is zero or more comma-separated ranges of\n\
                                 the form 'START-END' for 0 <= START < END\n\
      --skip-chmod             retain temporary permissions used during copy\n\
"), stdout);
      fprintf (stdout, _("\
      --split-size=MBYTES      size to split files for parallelization [%d]\n\
      --threads=NUMBER         number of OpenMP worker threads to use [%d]\n\
\n\
"), DEFAULT_SPLIT_SIZE, DEFAULT_THREADS);
#endif
/* TODO: these options temporarily disabled
TODO: fix hash-type to include stores
#if HAVE_LIBGCRYPT
      fputs (_("\
      --store-hash                 store hash in xattrs of each dst file\n\
"), stdout);
#endif
*/
      fputs (_("\
Standard options (mandatory arguments to long options are mandatory\n\
                  for short options too):\n\
"), stdout);
// < PZK
      fputs (_("\
  -a, --archive                same as -dR --preserve=all\n\
      --backup[=CONTROL]       make a backup of each existing destination file\n\
  -b                           like --backup but does not accept an argument\n\
      --copy-contents          copy contents of special files when recursive\n\
  -d                           same as --no-dereference --preserve=links\n\
"), stdout);
      fputs (_("\
  -f, --force                  if an existing destination file cannot be\n\
                                 opened, remove it and try again (redundant if\n\
                                 the -n option is used)\n\
  -i, --interactive            prompt before overwrite (overrides a previous -n\n\
                                  option)\n\
  -H                           follow command-line symbolic links in SOURCE\n\
"), stdout);
      fputs (_("\
  -l, --link                   link files instead of copying\n\
  -L, --dereference            always follow symbolic links in SOURCE\n\
"), stdout);
      fputs (_("\
  -n, --no-clobber             do not overwrite an existing file (overrides\n\
                                 a previous -i option)\n\
  -P, --no-dereference         never follow symbolic links in SOURCE\n\
"), stdout);
      fputs (_("\
  -p                           same as --preserve=mode,ownership,timestamps\n\
      --preserve[=ATTR_LIST]   preserve the specified attributes (default:\n\
                                 mode,ownership,timestamps), if possible\n\
                                 additional attributes: context, links, xattr,\n\
                                 all\n\
"), stdout);
      fputs (_("\
      --no-preserve=ATTR_LIST  don't preserve the specified attributes\n\
      --parents                use full source file name under DIRECTORY\n\
"), stdout);
      fputs (_("\
  -R, -r, --recursive          copy directories recursively\n\
      --reflink[=WHEN]         control clone/CoW copies. See below.\n\
      --remove-destination     remove each existing destination file before\n\
                                 attempting to open it (contrast with --force)\n\
"), stdout);
      fputs (_("\
      --sparse=WHEN            control creation of sparse files. See below.\n\
      --strip-trailing-slashes  remove any trailing slashes from each SOURCE\n\
                                 argument\n\
"), stdout);
      fputs (_("\
  -s, --symbolic-link          make symbolic links instead of copying\n\
  -S, --suffix=SUFFIX          override the usual backup suffix\n\
  -t, --target-directory=DIRECTORY  copy all SOURCE arguments into DIRECTORY\n\
  -T, --no-target-directory    treat DEST as a normal file\n\
"), stdout);
      fputs (_("\
  -u, --update                 copy only when the SOURCE file is newer\n\
                                 than the destination file or when the\n\
                                 destination file is missing\n\
  -v, --verbose                explain what is being done\n\
  -x, --one-file-system        stay on this file system\n\
"), stdout);
      fputs (HELP_OPTION_DESCRIPTION, stdout);
      fputs (VERSION_OPTION_DESCRIPTION, stdout);
      fputs (_("\
\n\
By default, sparse SOURCE files are detected by a crude heuristic and the\n\
corresponding DEST file is made sparse as well.  That is the behavior\n\
selected by --sparse=auto.  Specify --sparse=always to create a sparse DEST\n\
file whenever the SOURCE file contains a long enough sequence of zero bytes.\n\
Use --sparse=never to inhibit creation of sparse files.\n\
\n\
When --reflink[=always] is specified, perform a lightweight copy, where the\n\
data blocks are copied only when modified.  If this is not possible the copy\n\
fails, or if --reflink=auto is specified, fall back to a standard copy.\n\
"), stdout);
      fputs (_("\
\n\
The backup suffix is `~', unless set with --suffix or SIMPLE_BACKUP_SUFFIX.\n\
The version control method may be selected via the --backup option or through\n\
the VERSION_CONTROL environment variable.  Here are the values:\n\
\n\
"), stdout);
      fputs (_("\
  none, off       never make backups (even if --backup is given)\n\
  numbered, t     make numbered backups\n\
  existing, nil   numbered if numbered backups exist, simple otherwise\n\
  simple, never   always make simple backups\n\
"), stdout);
      fputs (_("\
\n\
As a special case, cp makes a backup of SOURCE when the force and backup\n\
options are given and SOURCE and DEST are the same name for an existing,\n\
regular file.\n\
"), stdout);
      emit_bug_reporting_address ();
    }
  exit (status);
}

/* Ensure that the parent directories of CONST_DST_NAME have the
   correct protections, for the --parents option.  This is done
   after all copying has been completed, to allow permissions
   that don't include user write/execute.

   SRC_OFFSET is the index in CONST_DST_NAME of the beginning of the
   source directory name.

   ATTR_LIST is a null-terminated linked list of structures that
   indicates the end of the filename of each intermediate directory
   in CONST_DST_NAME that may need to have its attributes changed.
   The command `cp --parents --preserve a/b/c d/e_dir' changes the
   attributes of the directories d/e_dir/a and d/e_dir/a/b to match
   the corresponding source directories regardless of whether they
   existed before the `cp' command was given.

   Return true if the parent of CONST_DST_NAME and any intermediate
   directories specified by ATTR_LIST have the proper permissions
   when done.  */

static bool
re_protect (char const *const_dst_name, size_t src_offset,
            struct dir_attr *attr_list, const struct cp_options *x)
{
  struct dir_attr *p;
  char *dst_name;		/* A copy of CONST_DST_NAME we can change. */
  char *src_name;		/* The source name in `dst_name'. */

  ASSIGN_STRDUPA (dst_name, const_dst_name);
  src_name = dst_name + src_offset;

  for (p = attr_list; p; p = p->next)
    {
      dst_name[p->slash_offset] = '\0';

      /* Adjust the times (and if possible, ownership) for the copy.
         chown turns off set[ug]id bits for non-root,
         so do the chmod last.  */

      if (x->preserve_timestamps)
        {
          struct timespec timespec[2];

          timespec[0] = get_stat_atime (&p->st);
          timespec[1] = get_stat_mtime (&p->st);

          if (utimens (dst_name, timespec))
            {
              error (0, errno, _("failed to preserve times for %s"),
                     quote (dst_name));
              return false;
            }
        }

      if (x->preserve_ownership)
        {
          if (lchown (dst_name, p->st.st_uid, p->st.st_gid) != 0)
            {
              if (! chown_failure_ok (x))
                {
                  error (0, errno, _("failed to preserve ownership for %s"),
                         quote (dst_name));
                  return false;
                }
              /* Failing to preserve ownership is OK. Still, try to preserve
                 the group, but ignore the possible error. */
              ignore_value (lchown (dst_name, -1, p->st.st_gid));
            }
        }

      if (x->preserve_mode)
        {
          if (copy_acl (src_name, -1, dst_name, -1, p->st.st_mode) != 0)
            return false;
        }
      else if (p->restore_mode)
        {
          if (lchmod (dst_name, p->st.st_mode) != 0)
            {
              error (0, errno, _("failed to preserve permissions for %s"),
                     quote (dst_name));
              return false;
            }
        }

      dst_name[p->slash_offset] = '/';
    }
  return true;
}

/* Ensure that the parent directory of CONST_DIR exists, for
   the --parents option.

   SRC_OFFSET is the index in CONST_DIR (which is a destination
   directory) of the beginning of the source directory name.
   Create any leading directories that don't already exist.
   If VERBOSE_FMT_STRING is nonzero, use it as a printf format
   string for printing a message after successfully making a directory.
   The format should take two string arguments: the names of the
   source and destination directories.
   Creates a linked list of attributes of intermediate directories,
   *ATTR_LIST, for re_protect to use after calling copy.
   Sets *NEW_DST if this function creates parent of CONST_DIR.

   Return true if parent of CONST_DIR exists as a directory with the proper
   permissions when done.  */

/* FIXME: Synch this function with the one in ../lib/mkdir-p.c.  */

static bool
make_dir_parents_private (char const *const_dir, size_t src_offset,
                          char const *verbose_fmt_string,
                          struct dir_attr **attr_list, bool *new_dst,
                          const struct cp_options *x)
{
  struct stat stats;
  char *dir;		/* A copy of CONST_DIR we can change.  */
  char *src;		/* Source name in DIR.  */
  char *dst_dir;	/* Leading directory of DIR.  */
  size_t dirlen;	/* Length of DIR.  */

  ASSIGN_STRDUPA (dir, const_dir);

  src = dir + src_offset;

  dirlen = dir_len (dir);
  dst_dir = alloca (dirlen + 1);
  memcpy (dst_dir, dir, dirlen);
  dst_dir[dirlen] = '\0';

  *attr_list = NULL;

  if (stat (dst_dir, &stats) != 0)
    {
      /* A parent of CONST_DIR does not exist.
         Make all missing intermediate directories. */
      char *slash;

      slash = src;
      while (*slash == '/')
        slash++;
      while ((slash = strchr (slash, '/')))
        {
          struct dir_attr *new IF_LINT (= NULL);
          bool missing_dir;

          *slash = '\0';
          missing_dir = (stat (dir, &stats) != 0);

          if (missing_dir | x->preserve_ownership | x->preserve_mode
              | x->preserve_timestamps)
            {
              /* Add this directory to the list of directories whose
                 modes might need fixing later. */
              struct stat src_st;
              int src_errno = (stat (src, &src_st) != 0
                               ? errno
                               : S_ISDIR (src_st.st_mode)
                               ? 0
                               : ENOTDIR);
              if (src_errno)
                {
                  error (0, src_errno, _("failed to get attributes of %s"),
                         quote (src));
                  return false;
                }

              new = xmalloc (sizeof *new);
              new->st = src_st;
              new->slash_offset = slash - dir;
              new->restore_mode = false;
              new->next = *attr_list;
              *attr_list = new;
            }

          if (missing_dir)
            {
              mode_t src_mode;
              mode_t omitted_permissions;
              mode_t mkdir_mode;

              /* This component does not exist.  We must set
                 *new_dst and new->st.st_mode inside this loop because,
                 for example, in the command `cp --parents ../a/../b/c e_dir',
                 make_dir_parents_private creates only e_dir/../a if
                 ./b already exists. */
              *new_dst = true;
              src_mode = new->st.st_mode;

              /* If the ownership or special mode bits might change,
                 omit some permissions at first, so unauthorized users
                 cannot nip in before the file is ready.  */
              omitted_permissions = (src_mode
                                     & (x->preserve_ownership
                                        ? S_IRWXG | S_IRWXO
                                        : x->preserve_mode
                                        ? S_IWGRP | S_IWOTH
                                        : 0));

              /* POSIX says mkdir's behavior is implementation-defined when
                 (src_mode & ~S_IRWXUGO) != 0.  However, common practice is
                 to ask mkdir to copy all the CHMOD_MODE_BITS, letting mkdir
                 decide what to do with S_ISUID | S_ISGID | S_ISVTX.  */
              mkdir_mode = src_mode & CHMOD_MODE_BITS & ~omitted_permissions;
              if (mkdir (dir, mkdir_mode) != 0)
                {
                  error (0, errno, _("cannot make directory %s"),
                         quote (dir));
                  return false;
                }
              else
                {
                  if (verbose_fmt_string != NULL)
                    printf (verbose_fmt_string, src, dir);
                }

              /* We need search and write permissions to the new directory
                 for writing the directory's contents. Check if these
                 permissions are there.  */

              if (lstat (dir, &stats))
                {
                  error (0, errno, _("failed to get attributes of %s"),
                         quote (dir));
                  return false;
                }


              if (! x->preserve_mode)
                {
                  if (omitted_permissions & ~stats.st_mode)
                    omitted_permissions &= ~ cached_umask ();
                  if (omitted_permissions & ~stats.st_mode
                      || (stats.st_mode & S_IRWXU) != S_IRWXU)
                    {
                      new->st.st_mode = stats.st_mode | omitted_permissions;
                      new->restore_mode = true;
                    }
                }

              if ((stats.st_mode & S_IRWXU) != S_IRWXU)
                {
                  /* Make the new directory searchable and writable.
                     The original permissions will be restored later.  */

                  if (lchmod (dir, stats.st_mode | S_IRWXU) != 0)
                    {
                      error (0, errno, _("setting permissions for %s"),
                             quote (dir));
                      return false;
                    }
                }
            }
          else if (!S_ISDIR (stats.st_mode))
            {
              error (0, 0, _("%s exists but is not a directory"),
                     quote (dir));
              return false;
            }
          else
            *new_dst = false;
          *slash++ = '/';

          /* Avoid unnecessary calls to `stat' when given
             file names containing multiple adjacent slashes.  */
          while (*slash == '/')
            slash++;
        }
    }

  /* We get here if the parent of DIR already exists.  */

  else if (!S_ISDIR (stats.st_mode))
    {
      error (0, 0, _("%s exists but is not a directory"), quote (dst_dir));
      return false;
    }
  else
    {
      *new_dst = false;
    }
  return true;
}

/* FILE is the last operand of this command.
   Return true if FILE is a directory.
   But report an error and exit if there is a problem accessing FILE,
   or if FILE does not exist but would have to refer to an existing
   directory if it referred to anything at all.

   If the file exists, store the file's status into *ST.
   Otherwise, set *NEW_DST.  */

static bool
target_directory_operand (char const *file, struct stat *st, bool *new_dst)
{
  int err = (stat (file, st) == 0 ? 0 : errno);
  bool is_a_dir = !err && S_ISDIR (st->st_mode);
  if (err)
    {
      if (err != ENOENT)
        error (EXIT_FAILURE, err, _("accessing %s"), quote (file));
      *new_dst = true;
    }
  return is_a_dir;
}

// PZK >
void print_hash(const struct cp_options *x, copy_reg_t *crt)
{
    size_t i;

    // put non-standard output in comments
    if (crt->nsplits > 1 || crt->partial) {
        printf("#mutil#");
        if (crt->partial)
            printf("%lld-%lld", crt->start_offset, crt->stop_offset);
        printf("#");
    }

    /* Output a leading backslash if the file name contains
       a newline or backslash.  */
    if (strchr(crt->dst_name, '\n') || strchr(crt->dst_name, '\\'))
        putchar ('\\');

    size_t bytes = x->hash_size;
    if (x->check_tree) bytes *= crt->nsplits;
             
    for (size_t i = 0; i < bytes; ++i)
        printf ("%02x", crt->hash_stack[i]);

    putchar (' ');
/*TODO: do something with this binary stuff
    if (file_is_binary)
      putchar ('*');
    else
*/
      putchar (' ');

    /* Translate each NEWLINE byte to the string, "\\n",
       and each backslash to "\\\\".  */
    for (i = 0; i < strlen(crt->dst_name); ++i) {
        switch (crt->dst_name[i]) {
        case '\n':
            fputs("\\n", stdout);
            break;
        case '\\':
            fputs("\\\\", stdout);
            break;
        default:
            putchar(crt->dst_name[i]);
            break;
        }
    }
    putchar ('\n');
}

/* Make ancestor directory DIR, whose last file name component is
   COMPONENT, with options OPTIONS.  Assume the working directory is
   COMPONENT's parent.  */

static int
make_ancestor (char const *dir, char const *component, void *options)
{
  return mkdir (component, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
}

/* unescape() based on curl_easy_escape() to which the following applies
COPYRIGHT AND PERMISSION NOTICE

Copyright (c) 1996 - 2009, Daniel Stenberg, <daniel@haxx.se>.

All rights reserved.

Permission to use, copy, modify, and distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN
NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of a copyright holder shall not
be used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization of the copyright holder.
*/

/*
 * Unescapes the given URL escaped string of given length. Returns a
 * pointer to a malloced string.
 * If length == 0, the length is assumed to be strlen(string).
 */
char *unescape(const char *string, int length)
{
  int alloc = (length?length:(int)strlen(string))+1;
  char *ns = xmalloc(alloc);
  unsigned char in;
  int strindex=0;
  long hex;

  if( !ns )
    return NULL;

  while(--alloc > 0) {
    in = *string;
    if(('%' == in) && isxdigit(string[1]) && isxdigit(string[2])) {
      /* this is two hexadecimal digits following a '%' */
      char hexstr[3];
      char *ptr;
      hexstr[0] = string[1];
      hexstr[1] = string[2];
      hexstr[2] = 0;

      hex = strtol(hexstr, &ptr, 16);

      in = (unsigned char)hex; /* this long is never bigger than 255 anyway */

      string+=2;
      alloc-=2;
    }

    ns[strindex++] = in;
    string++;
  }
  ns[strindex]=0; /* terminate it */

  return ns;
}
// < PZK

/* Scan the arguments, and copy each by calling copy.
   Return true if successful.  */

static bool
do_copy (int n_files, char **file, const char *target_directory,
         bool no_target_directory, struct cp_options *x)
{
  struct stat sb;
  bool new_dst = false;
  bool ok = true;

// PZK >
  if (!x->mgr_port && !x->read_stdin && n_files <= !target_directory)
// < PZK
    {
      if (n_files <= 0)
        error (0, 0, _("missing file operand"));
      else
        error (0, 0, _("missing destination file operand after %s"),
               quote (file[0]));
      usage (EXIT_FAILURE);
    }

// PZK >
  if (!x->mgr_port && !x->read_stdin && no_target_directory)
// < PZK
    {
      if (target_directory)
        error (EXIT_FAILURE, 0,
               _("cannot combine --target-directory (-t) "
                 "and --no-target-directory (-T)"));
      if (2 < n_files)
        {
          error (0, 0, _("extra operand %s"), quote (file[2]));
          usage (EXIT_FAILURE);
        }
    }
// PZK >
  else if (!x->mgr_port && !x->read_stdin && !target_directory)
// < PZK
    {
      if (2 <= n_files
          && target_directory_operand (file[n_files - 1], &sb, &new_dst))
        target_directory = file[--n_files];
      else if (2 < n_files)
        error (EXIT_FAILURE, 0, _("target %s is not a directory"),
               quote (file[n_files - 1]));
    }

// PZK >
#ifdef _OPENMP
  int pid = 0, procs = 1;
  int hash_stat_done = 1;
  int main_done = 0;
# if HAVE_LIBMPI
  if (x->mpi) {
    MPI_Init(NULL, NULL);
    MPI_Comm_rank(MPI_COMM_WORLD, &pid);
    MPI_Comm_size(MPI_COMM_WORLD, &procs);
    // add a thread for MPI handler on main node
    if (pid == 0) x->threads++;
  }
# endif
  // add a thread for TCP handler on main node
  if (x->listen_port) x->threads++;
  // add a thread for file/TCP-MPI handler on main/other nodes
  x->threads++;
  // add a thread for stat/hash handler on main node
  if (!x->mgr_port && pid == 0 &&
        (x->print_stats || x->print_hash || x->store_hash)) {
    x->threads++;
    hash_stat_done = 0;
  }

  omp_set_num_threads(x->threads);
  bool oks[x->threads];
  omp_q_t task_q;
  omp_q_init(&task_q, x->threads, sizeof(copy_reg_t));
  x->task_q = &task_q;
  omp_q_t open_q;
  omp_q_init(&open_q, x->threads, sizeof(void *));
  x->open_q = &open_q;
  omp_q_t send_q;
  omp_q_init(&send_q, x->threads, sizeof(void *));
  x->send_q = &send_q;

# if HAVE_LIBGCRYPT
  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
  if (!gcry_check_version(GCRYPT_VERSION))
    error (EXIT_FAILURE, 0, _("libgcrypt version mismatch"));
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control(GCRYCTL_ENABLE_M_GUARD, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
# endif
# pragma omp parallel
{
  int tid = omp_get_thread_num();
  oks[tid] = true;
  if (!x->mgr_port && pid == 0 && tid == 2 &&
        (x->print_stats || x->print_hash || x->store_hash)) {
    ////////////////////////////////////
    // stat/hash handler on main node //
    ////////////////////////////////////
    struct timespec tts[2];
    if (x->print_stats) {
      fprintf(stderr, _("      size        rd_mbs  wt_mbs  cp_mbs  file\n"));
      fprintf(stderr, _("      ----        ------  ------  ------  ----\n"));
      clock_gettime(CLOCK_REALTIME, &tts[0]);
    }
    off_t tsize = 0;
    int maxcrts = 128;
    copy_reg_t **crts = xcalloc(maxcrts, sizeof(copy_reg_t *));
    int ncrts = 0;
    long long done_tasks = 0;
    while (!main_done || *x->hash_stat_tasks > done_tasks) {
      copy_reg_t *crt = omp_q_pop(&send_q);
      if (crt != NULL && crt->split != crt->nsplits) done_tasks++;
      if (crt == NULL || crt->dst_name == NULL) {
        //TODO: do something with error?
        continue;
      }
      if (x->print_stats && crt->split != crt->nsplits) {
        tsize += crt->stop_offset - crt->start_offset;
        double mb = (crt->stop_offset - crt->start_offset) / 1000.0 / 1000.0;
        fprintf(stderr, _("%16lld  %6.1f  %6.1f  %6.1f  %s"),
            crt->stop_offset - crt->start_offset, mb / crt->read_time,
            mb / crt->write_time, mb / crt->copy_time, crt->dst_name);
        if (crt->nsplits > 1)
            fprintf(stderr, _(" (%lu/%lu)"), crt->split + 1, crt->nsplits);
        fprintf(stderr, _("\n"));
      }

      if (x->print_hash && crt->nsplits == 1) {
        print_hash(x, crt);
      }

      if (!x->print_hash || crt->nsplits <= 1) {
        free(crt->src_name);
        free(crt->dst_name);
        free(crt->hash_stack);
        free(crt);
        continue;
      }

      int index;
      int empty = -1;
      // find existing entry and/or free slot
      for (index = 0; index < maxcrts; index++) {
          if (crts[index] == NULL) {
              if (empty < 0) empty = index;
              continue;
          }
          if (!strcmp(crt->dst_name, crts[index]->dst_name)) break;
      }
      if (index >= maxcrts) {
          // this is the first split received
          if (empty == -1) {
              // no free slot found so expand array
              maxcrts *= 2;
              //TODO: should probably error out if array gets too big
              xrealloc(crts, maxcrts * sizeof(copy_reg_t *));
              bzero(&crts[maxcrts / 2], maxcrts / 2 * sizeof(copy_reg_t *));
              empty = index;
          }
          // first crt has special field values including
          //   split = nsplits, stop_offset = file size,
          //   dest_desc = open fd, and hash_stack of size nsplits * hash size
          crts[empty] = crt;
      } else {
# if HAVE_LIBGCRYPT
        // copy final hash onto shared hash stack
        memcpy(&crts[index]->hash_stack[crt->split * x->hash_size],
            crt->hash_stack, x->hash_size);
        free(crt->hash_stack);
# endif
        free(crt->src_name);
        free(crt->dst_name);
        free(crt);
        crt = crts[index];
        // this works because split will be nsplits in first crt received
        if (--crt->split == 0) {
# if HAVE_LIBGCRYPT
            // finalize hash if last
            gcry_md_hd_t ctx;
            gcry_md_open(&ctx, x->hash_type, 0);
            hash_tree_t htt;
            htt.n_hash_total = 0;
            htt.hash_ctx = &ctx;
            htt.hash_ctx_len = 0;
//TODO:            if (x->store_hash) htt.xattr = xmalloc(ATTR_MAX_VALUELEN);
            htt.xattr_len = 0;
            // this works because dest_desc will be open in first crt received
            htt.fd = crt->dest_desc;
            htt.stack_len = 0;
            // don't compute root of tree when printing subtrees
            if (!x->check_tree)
                hash_final(&htt, crt, x, 0, crt->nsplits,
                    crt->stop_offset - crt->start_offset);
            // print hash
            if (x->print_hash) {
                print_hash(x, crt);
            }
            // clean up
            gcry_md_close(ctx);
            if (x->store_hash) {
                close(crt->dest_desc);
                free(htt.xattr);
            }
            free(crt->hash_stack);
# endif
            free(crt->src_name);
            free(crt->dst_name);
            free(crt);
            crts[index] = NULL;
            //TODO: if last, then set done for tcp, etc.
        }
      }
    }
    if (x->print_stats) {
        clock_gettime(CLOCK_REALTIME, &tts[1]);
        double tt = (double) (
            (double) tts[1].tv_sec + (double) tts[1].tv_nsec / (double) 1.0e9 -
            (double) tts[0].tv_sec - (double) tts[0].tv_nsec / (double) 1.0e9);
        double mb = tsize / 1000.0 / 1000.0;
        fprintf(stderr, _("      ----        ------  ------  ------  ----\n"));
        fprintf(stderr, _("%16lld                  %6.1f  total\n"),
            tsize, mb / tt);
    }
    hash_stat_done = 1;
# if HAVE_LIBMPI
    if (x->mpi) {
        // send message to MPI handler on main node to break out of
        // a final receive called just before hash_stat_done is set
        long long sz = -1;
        MPI_Send(&sz, 1, MPI_LONG_LONG, 0, 1, MPI_COMM_WORLD);
    }
# endif
# if HAVE_LIBMPI
  } else if (pid != 0 && tid == 0) {
    ////////////////////////////////
    // MPI handler on other nodes //
    ////////////////////////////////
    int nulls = 0;
    int null_task = 0;
    int nonnull_task = 0;

    while (nulls < x->threads - 1) {
      copy_reg_t *crt = omp_q_pop(&send_q);
      if (crt == NULL && null_task) {
          nulls++;
          omp_q_push(&task_q, NULL);
          continue;
      } else if (crt != NULL) {
          nonnull_task = 1;
      }

      size_t src_size, dst_size;
      long long sz;
      int pos = 0;

      if (crt != NULL) {
        // send final status with times and hash
        src_size = strlen(crt->src_name) + 1;
        dst_size = strlen(crt->dst_name) + 1;
        sz = src_size + dst_size + x->hash_size + sizeof(copy_reg_t);
        MPI_Send(&sz, 1, MPI_LONG_LONG, 0, 1, MPI_COMM_WORLD);

        // pack crt into one big byte array
        char pack[sz];
        // this assumes same arch on client/server
        MPI_Pack(&src_size, sizeof(src_size),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&dst_size, sizeof(dst_size),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(crt->src_name, src_size,
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(crt->dst_name, dst_size,
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        if (x->hash_size)
            MPI_Pack(crt->hash_stack, x->hash_size,
                MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->dst_mode, sizeof(crt->dst_mode),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->src_atime, sizeof(crt->src_atime),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->src_mtime, sizeof(crt->src_mtime),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->dst_blksize, sizeof(crt->dst_blksize),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->read_time, sizeof(crt->read_time),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->write_time, sizeof(crt->write_time),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->copy_time, sizeof(crt->copy_time),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->start_offset, sizeof(crt->start_offset),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->stop_offset, sizeof(crt->stop_offset),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->nsplits, sizeof(crt->nsplits),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&crt->split, sizeof(crt->split),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);

        MPI_Send(pack, pos, MPI_PACKED, 0, 1, MPI_COMM_WORLD);

        free(crt->src_name);
        free(crt->dst_name);
        free(crt->hash_stack);
        free(crt);
      } else {
        // send task request
        sz = 0;
        MPI_Send(&sz, 1, MPI_LONG_LONG, 0, 1, MPI_COMM_WORLD);

        // receive task request
        MPI_Status stat;
        int rc = MPI_Recv(&sz, 1, MPI_LONG_LONG, 0, 1, MPI_COMM_WORLD, &stat);
        if (rc || sz == 0) {
            null_task = 1;
            nulls++;
            omp_q_push(&task_q, NULL);
        } else {
            // unpack crt from one big byte array
            char pack[sz];
            MPI_Recv(pack, sz, MPI_PACKED, 0, 1, MPI_COMM_WORLD, &stat);
            // this assumes same arch on client/server
            MPI_Unpack(pack, sz, &pos, &src_size, sizeof(src_size),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &dst_size, sizeof(dst_size),
                MPI_BYTE, MPI_COMM_WORLD);

            crt = xmalloc(sizeof(copy_reg_t));
            crt->src_name = xmalloc(src_size);
            crt->dst_name = xmalloc(dst_size);
            crt->hash_stack = xmalloc(x->hash_size);
            MPI_Unpack(pack, sz, &pos, crt->src_name, src_size,
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, crt->dst_name, dst_size,
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->dst_mode, sizeof(crt->dst_mode),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->src_atime, sizeof(crt->src_atime),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->src_mtime, sizeof(crt->src_mtime),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->dst_blksize, sizeof(crt->dst_blksize),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->read_time, sizeof(crt->read_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->write_time, sizeof(crt->write_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->copy_time, sizeof(crt->copy_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->start_offset, sizeof(crt->start_offset),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->stop_offset, sizeof(crt->stop_offset),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->nsplits, sizeof(crt->nsplits),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->split, sizeof(crt->split),
                MPI_BYTE, MPI_COMM_WORLD);

            omp_q_push(&task_q, crt);
            omp_q_pop(&open_q);
            sz = 0;
            MPI_Send(&sz, 1, MPI_LONG_LONG, 0, 1, MPI_COMM_WORLD);
        }
      }
    }
  } else if (x->mpi && pid == 0 && tid == 1) {
    //////////////////////////////
    // MPI handler on main node //
    //////////////////////////////
    int null_task = 0;
    MPI_Status stat;
    long long sz;
    int mpi_recv = 0;

    while (!main_done || !hash_stat_done || x->mpi && mpi_recv < 2) {
        if (MPI_Recv(&sz, 1, MPI_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG,
                MPI_COMM_WORLD, &stat)) break;

        size_t src_size, dst_size;
        copy_reg_t *crt;
        int pos = 0;

        if (sz > 0) {
            // unpack crt from one big byte array
            char pack[sz];
            if (MPI_Recv(pack, sz, MPI_PACKED, stat.MPI_SOURCE,
                    stat.MPI_TAG, MPI_COMM_WORLD, &stat)) continue;
            // this assumes same arch on client/server
            MPI_Unpack(pack, sz, &pos, &src_size, sizeof(src_size),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &dst_size, sizeof(dst_size),
                MPI_BYTE, MPI_COMM_WORLD);

            crt = xmalloc(sizeof(copy_reg_t));
            crt->src_name = xmalloc(src_size);
            crt->dst_name = xmalloc(dst_size);
            crt->hash_stack = xmalloc(x->hash_size);
            MPI_Unpack(pack, sz, &pos, crt->src_name, src_size,
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, crt->dst_name, dst_size,
                MPI_BYTE, MPI_COMM_WORLD);
            if (x->hash_size)
                MPI_Unpack(pack, sz, &pos, crt->hash_stack, x->hash_size,
                    MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->dst_mode, sizeof(crt->dst_mode),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->src_atime, sizeof(crt->src_atime),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->src_mtime, sizeof(crt->src_mtime),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->dst_blksize, sizeof(crt->dst_blksize),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->read_time, sizeof(crt->read_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->write_time, sizeof(crt->write_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->copy_time, sizeof(crt->copy_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->start_offset, sizeof(crt->start_offset),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->stop_offset, sizeof(crt->stop_offset),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->nsplits, sizeof(crt->nsplits),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &crt->split, sizeof(crt->split),
                MPI_BYTE, MPI_COMM_WORLD);

            omp_q_push(&send_q, crt);
        } else if (sz == 0) {
            crt = null_task ? NULL : omp_q_pop(&task_q);
            if (crt == NULL) {
                null_task = 1;
                sz = 0;
                MPI_Send(&sz, 1, MPI_LONG_LONG, stat.MPI_SOURCE,
                    stat.MPI_TAG, MPI_COMM_WORLD);
            } else {
                src_size = strlen(crt->src_name) + 1;
                dst_size = strlen(crt->dst_name) + 1;
                sz = src_size + dst_size + sizeof(copy_reg_t);
                MPI_Send(&sz, 1, MPI_LONG_LONG, stat.MPI_SOURCE,
                    stat.MPI_TAG, MPI_COMM_WORLD);
                // pack crt into one big byte array
                char pack[sz];
                // this assumes same arch on client/server
                MPI_Pack(&src_size, sizeof(src_size),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&dst_size, sizeof(dst_size),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(crt->src_name, src_size,
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(crt->dst_name, dst_size,
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->dst_mode, sizeof(crt->dst_mode),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->src_atime, sizeof(crt->src_atime),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->src_mtime, sizeof(crt->src_mtime),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->dst_blksize, sizeof(crt->dst_blksize),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->read_time, sizeof(crt->read_time),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->write_time, sizeof(crt->write_time),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->copy_time, sizeof(crt->copy_time),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->start_offset, sizeof(crt->start_offset),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->stop_offset, sizeof(crt->stop_offset),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->nsplits, sizeof(crt->nsplits),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&crt->split, sizeof(crt->split),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);

                MPI_Send(pack, pos, MPI_PACKED, stat.MPI_SOURCE, stat.MPI_TAG,
                    MPI_COMM_WORLD);
                // wait for message indicating open
                //TODO: need timeout here
                MPI_Recv(&sz, 1, MPI_LONG_LONG, stat.MPI_SOURCE, stat.MPI_TAG,
                    MPI_COMM_WORLD, &stat);
                // indicate that file has been opened to local master
                omp_q_push(&open_q, NULL);
                free(crt->src_name);
                free(crt->dst_name);
                free(crt->hash_stack);
                free(crt);
            }
        } else {
            // main and hash/stat done message to prevent deadlock
            mpi_recv++;
        }
    }
# endif
  } else if (tid != 0) {
    ///////////////////////////////
    // copy handler on all nodes //
    ///////////////////////////////
    // indicate ready for request on other nodes
    if (x->mgr_port || pid != 0) omp_q_push(&send_q, NULL);
    copy_reg_t *crt;
    while ((crt = omp_q_pop(&task_q)) != NULL) {
      crt->source_desc =
        open(crt->src_name, (O_RDONLY | O_BINARY | x->read_mode |
          (x->dereference == DEREF_NEVER ? O_NOFOLLOW : 0)));
      if (crt->source_desc < 0 && x->read_mode)
        crt->source_desc = open(crt->src_name, (O_RDONLY | O_BINARY |
          (x->dereference == DEREF_NEVER ? O_NOFOLLOW : 0)));
      if (crt->source_desc < 0)
        error(0, errno, _("warning: unable to open %s for read"), quote(crt->src_name));
      crt->dest_desc = open(crt->dst_name, O_WRONLY | O_BINARY | x->write_mode);
      if (crt->dest_desc < 0)
        error(0, errno, _("warning: unable to open %s for write"), quote(crt->dst_name));
      if (lseek(crt->source_desc, crt->start_offset, SEEK_SET) < 0)
        error(0, errno, _("warning: unable to seek in %s"), quote(crt->src_name));
      if (lseek(crt->dest_desc, crt->start_offset, SEEK_SET) < 0)
        error(0, errno, _("warning: unable to seek in %s"), quote(crt->dst_name));
      //TODO: additional error handling if can't open or seek?
      // indicate that file has been opened
      omp_q_push(&open_q, NULL);
      struct timespec ts[2];
      if (x->print_stats) clock_gettime(CLOCK_REALTIME, &ts[0]);
      oks[tid] &= copy_reg_task(crt, x);
      if (x->print_stats) {
        clock_gettime(CLOCK_REALTIME, &ts[1]);
        crt->copy_time = (double) (
          (double) ts[1].tv_sec + (double) ts[1].tv_nsec / (double) 1.0e9 -
          (double) ts[0].tv_sec - (double) ts[0].tv_nsec / (double) 1.0e9);
      }
      if (x->print_stats || x->print_hash ||
            x->store_hash && crt->nsplits > 1) {
        omp_q_push(&send_q, crt);
      } else {
        free(crt->src_name);
        free(crt->dst_name);
        free(crt->hash_stack);
        free(crt);
      }
      // indicate ready for request on other nodes
      if (x->mgr_port || pid != 0) omp_q_push(&send_q, NULL);
    }
  } else {
#endif
// < PZK

  if (target_directory)
    {
      /* cp file1...filen edir
         Copy the files `file1' through `filen'
         to the existing directory `edir'. */
      int i;

      /* Initialize these hash tables only if we'll need them.
         The problems they're used to detect can arise only if
         there are two or more files to copy.  */
      if (2 <= n_files)
        {
          dest_info_init (x);
          src_info_init (x);
        }

      for (i = 0; i < n_files; i++)
        {
          char *dst_name;
          bool parent_exists = true;  /* True if dir_name (dst_name) exists. */
          struct dir_attr *attr_list;
          char *arg_in_concat = NULL;
          char *arg = file[i];

          /* Trailing slashes are meaningful (i.e., maybe worth preserving)
             only in the source file names.  */
          if (remove_trailing_slashes)
            strip_trailing_slashes (arg);

          if (parents_option)
            {
              char *arg_no_trailing_slash;

              /* Use `arg' without trailing slashes in constructing destination
                 file names.  Otherwise, we can end up trying to create a
                 directory via `mkdir ("dst/foo/"...', which is not portable.
                 It fails, due to the trailing slash, on at least
                 NetBSD 1.[34] systems.  */
              ASSIGN_STRDUPA (arg_no_trailing_slash, arg);
              strip_trailing_slashes (arg_no_trailing_slash);

              /* Append all of `arg' (minus any trailing slash) to `dest'.  */
              dst_name = file_name_concat (target_directory,
                                           arg_no_trailing_slash,
                                           &arg_in_concat);

              /* For --parents, we have to make sure that the directory
                 dir_name (dst_name) exists.  We may have to create a few
                 leading directories. */
              parent_exists =
                (make_dir_parents_private
                 (dst_name, arg_in_concat - dst_name,
                  (x->verbose ? "%s -> %s\n" : NULL),
                  &attr_list, &new_dst, x));
            }
          else
            {
              char *arg_base;
              /* Append the last component of `arg' to `target_directory'.  */

              ASSIGN_BASENAME_STRDUPA (arg_base, arg);
              /* For `cp -R source/.. dest', don't copy into `dest/..'. */
              dst_name = (STREQ (arg_base, "..")
                          ? xstrdup (target_directory)
                          : file_name_concat (target_directory, arg_base,
                                              NULL));
            }

          if (!parent_exists)
            {
              /* make_dir_parents_private failed, so don't even
                 attempt the copy.  */
              ok = false;
            }
          else
            {
              bool copy_into_self;
              ok &= copy (arg, dst_name, new_dst, x, &copy_into_self, NULL);

              if (parents_option)
                ok &= re_protect (dst_name, arg_in_concat - dst_name,
                                  attr_list, x);
            }

          if (parents_option)
            {
              while (attr_list)
                {
                  struct dir_attr *p = attr_list;
                  attr_list = attr_list->next;
                  free (p);
                }
            }

          free (dst_name);
        }
    }
// PZK >
  else if (x->read_stdin)
    {
      /* Start with a buffer larger than PATH_MAX, but beware of systems
         on which PATH_MAX is very large -- e.g., INT_MAX.  */
      size_t buf_max = MIN(2 * PATH_MAX, 32 * 1024);
      char *buf = xmalloc(buf_max);

      char *new_dest;
      char *source;
      char *dest;
      bool unused;

      while (fgets(buf, buf_max, stdin) != NULL) {
        buf[strcspn(buf, "\n")] = '\0';
        if (buf[0] == '\0') {
            //TODO: error handling if string too long
            continue;
        }
        size_t ifile2 = strcspn(buf, " ");
        if (buf[ifile2] == '\0') continue;
        buf[ifile2++] = '\0';
        size_t irange = strcspn(&buf[ifile2], " ");
        if (buf[ifile2 + irange] == '\0') {
            irange = 0;
        } else {
            irange = ifile2 + irange;
            buf[irange++] = '\0';
        }
        source = unescape(buf, 0);
        dest = unescape(&buf[ifile2], 0);
        if (source == NULL || dest == NULL) {
            //TODO: error handling if can't unescape
            continue;
        }

        /* When the force and backup options have been specified and
           the source and destination are the same name for an existing
           regular file, convert the user's command, e.g.,
           `cp --force --backup foo foo' to `cp --force foo fooSUFFIX'
           where SUFFIX is determined by any version control options used.  */

        if (x->unlink_dest_after_failed_open
            && x->backup_type != no_backups
            && STREQ (source, dest)
            && !new_dst && S_ISREG (sb.st_mode))
          {
            static struct cp_options x_tmp;

            new_dest = find_backup_file_name (dest, x->backup_type);
            /* Set x->backup_type to `no_backups' so that the normal backup
               mechanism is not used when performing the actual copy.
               backup_type must be set to `no_backups' only *after* the above
               call to find_backup_file_name -- that function uses
               backup_type to determine the suffix it applies.  */
            x_tmp = *x;
            x_tmp.backup_type = no_backups;
            x = &x_tmp;
          }
        else
          {
            new_dest = dest;
          }

        bool save_working_directory =
          ! (IS_ABSOLUTE_FILE_NAME (source) && IS_ABSOLUTE_FILE_NAME (new_dest));
        int status = EXIT_SUCCESS;

        struct savewd wd;
        savewd_init (&wd);
        if (! save_working_directory)
            savewd_finish (&wd);

        if (mkancesdirs (new_dest, &wd, make_ancestor, x) == -1)
          {
            error (0, errno, _("cannot create directory %s"), new_dest);
            status = EXIT_FAILURE;
          }

        if (save_working_directory)
          {
            int restore_result = savewd_restore (&wd, status);
            int restore_errno = errno;
            savewd_finish (&wd);
            if (EXIT_SUCCESS < restore_result)
                //TODO: error handling?
                continue;
            if (restore_result < 0 && status == EXIT_SUCCESS)
              {
                error (0, restore_errno, _("cannot create directory %s"), new_dest);
                //TODO: error handling?
                continue;
              }
          }

        if (irange > 0) {
            off_t x1, x2;
            while (sscanf(&buf[irange], "%lld-%lld", &x1, &x2) == 2) {
                x->offset = x1;
                x->length = x2 - x1;
                ok &= copy (source, new_dest, 0, x, &unused, NULL);
                irange += strcspn(&buf[irange], ",");
                if (buf[irange] == ',') irange++;
            }
        } else {
            x->offset = 0;
            x->length = 0;
            ok = copy (source, new_dest, 0, x, &unused, NULL);
        }
        free(source);
        free(dest);
      }
    }
// < PZK
  else /* !target_directory */
    {
      char const *new_dest;
      char const *source = file[0];
      char const *dest = file[1];
      bool unused;

      if (parents_option)
        {
          error (0, 0,
                 _("with --parents, the destination must be a directory"));
          usage (EXIT_FAILURE);
        }

      /* When the force and backup options have been specified and
         the source and destination are the same name for an existing
         regular file, convert the user's command, e.g.,
         `cp --force --backup foo foo' to `cp --force foo fooSUFFIX'
         where SUFFIX is determined by any version control options used.  */

      if (x->unlink_dest_after_failed_open
          && x->backup_type != no_backups
          && STREQ (source, dest)
          && !new_dst && S_ISREG (sb.st_mode))
        {
          static struct cp_options x_tmp;

          new_dest = find_backup_file_name (dest, x->backup_type);
          /* Set x->backup_type to `no_backups' so that the normal backup
             mechanism is not used when performing the actual copy.
             backup_type must be set to `no_backups' only *after* the above
             call to find_backup_file_name -- that function uses
             backup_type to determine the suffix it applies.  */
          x_tmp = *x;
          x_tmp.backup_type = no_backups;
          x = &x_tmp;
        }
      else
        {
          new_dest = dest;
        }

      ok = copy (source, new_dest, 0, x, &unused, NULL);
    }
// PZK >
#ifdef _OPENMP
    // indicate that main thread is done traversing file system
    main_done = 1;
    // send terminating NULL task to stat/hash thread
    omp_q_push(&send_q, NULL);
    // send terminating NULL task to all worker threads
    for (int i = 0; i < x->threads - 1; i++)
        omp_q_push(&task_q, NULL);
# if HAVE_LIBMPI
    if (x->mpi) {
        // send message to MPI handler on main node to break out of
        // a final receive called just before main_done is set
        long long sz = -1;
        MPI_Send(&sz, 1, MPI_LONG_LONG, 0, 1, MPI_COMM_WORLD);
    }
# endif
  }
}

# if HAVE_LIBMPI
  if (x->mpi) MPI_Finalize();
# endif

  // destroy all queues
  omp_q_destroy(&send_q);
  omp_q_destroy(&open_q);
  omp_q_destroy(&task_q);

  //TODO: this no longer works with mpi/tcp
  // reduce oks array to single value
  for (int i = 0; i < x->threads; i++)
    ok &= oks[i];
// < PZK
#endif

  return ok;
}

static void
cp_option_init (struct cp_options *x)
{
  cp_options_default (x);
// PZK >
  x->buffer_size = DEFAULT_BUFFER_SIZE * 1024 * 1024;
  x->check_tree = false;
#if DEFAULT_DOUBLE_BUFFER
  x->double_buffer = true;
#else
  x->double_buffer = false;
#endif
  x->fadvise_read = false;
  x->fadvise_write = false;
  x->hash_size = 0;
  x->hash_stat_tasks = xcalloc(1, sizeof(long long));
#if HAVE_LIBGCRYPT
  x->hash_type = DEFAULT_HASH_TYPE;
#endif
  x->length = 0;
  x->listen_port = 0;
  x->mg_file = 0;
  x->mgr_ai = NULL;
  x->mgr_port = 0;
  x->mpi = false;
  x->offset = 0;
  x->open_q = NULL;
  x->pass = NULL;
  x->print_hash = false;
  x->print_stats = false;
  x->pw_file = 0;
#if DEFAULT_DIRECT_READ
  x->read_mode = O_DIRECT;
#else
  x->read_mode = 0;
#endif
  x->read_stdin = false;
  x->skip_chmod = false;
  x->split_size = DEFAULT_SPLIT_SIZE * 1024 * 1024;
  x->hash_leaf_size = x->split_size; // this must follow split_size
  x->store_hash = false;
  x->task_q = NULL;
  x->threads = DEFAULT_THREADS;
  x->user = NULL;
#if DEFAULT_DIRECT_WRITE
  x->write_mode = O_DIRECT;
#else
  x->write_mode = 0;
#endif
// < PZK
  x->copy_as_regular = true;
  x->dereference = DEREF_UNDEFINED;
  x->unlink_dest_before_opening = false;
  x->unlink_dest_after_failed_open = false;
  x->hard_link = false;
  x->interactive = I_UNSPECIFIED;
  x->move_mode = false;
  x->one_file_system = false;
  x->reflink_mode = REFLINK_NEVER;

  x->preserve_ownership = false;
  x->preserve_links = false;
  x->preserve_mode = false;
  x->preserve_timestamps = false;
  x->preserve_security_context = false;
  x->require_preserve_context = false;
  x->preserve_xattr = false;
  x->reduce_diagnostics = false;
  x->require_preserve_xattr = false;

  x->require_preserve = false;
  x->recursive = false;
  x->sparse_mode = SPARSE_AUTO;
  x->symbolic_link = false;
  x->set_mode = false;
  x->mode = 0;

  /* Not used.  */
  x->stdin_tty = false;

  x->update = false;
  x->verbose = false;

  /* By default, refuse to open a dangling destination symlink, because
     in general one cannot do that safely, give the current semantics of
     open's O_EXCL flag, (which POSIX doesn't even allow cp to use, btw).
     But POSIX requires it.  */
  x->open_dangling_dest_symlink = getenv ("POSIXLY_CORRECT") != NULL;

  x->dest_info = NULL;
  x->src_info = NULL;
}

/* Given a string, ARG, containing a comma-separated list of arguments
   to the --preserve option, set the appropriate fields of X to ON_OFF.  */
static void
decode_preserve_arg (char const *arg, struct cp_options *x, bool on_off)
{
  enum File_attribute
    {
      PRESERVE_MODE,
      PRESERVE_TIMESTAMPS,
      PRESERVE_OWNERSHIP,
      PRESERVE_LINK,
      PRESERVE_CONTEXT,
      PRESERVE_XATTR,
      PRESERVE_ALL
    };
  static enum File_attribute const preserve_vals[] =
    {
      PRESERVE_MODE, PRESERVE_TIMESTAMPS,
      PRESERVE_OWNERSHIP, PRESERVE_LINK, PRESERVE_CONTEXT, PRESERVE_XATTR,
      PRESERVE_ALL
    };
  /* Valid arguments to the `--preserve' option. */
  static char const* const preserve_args[] =
    {
      "mode", "timestamps",
      "ownership", "links", "context", "xattr", "all", NULL
    };
  ARGMATCH_VERIFY (preserve_args, preserve_vals);

  char *arg_writable = xstrdup (arg);
  char *s = arg_writable;
  do
    {
      /* find next comma */
      char *comma = strchr (s, ',');
      enum File_attribute val;

      /* If we found a comma, put a NUL in its place and advance.  */
      if (comma)
        *comma++ = 0;

      /* process S.  */
      val = XARGMATCH ("--preserve", s, preserve_args, preserve_vals);
      switch (val)
        {
        case PRESERVE_MODE:
          x->preserve_mode = on_off;
          break;

        case PRESERVE_TIMESTAMPS:
          x->preserve_timestamps = on_off;
          break;

        case PRESERVE_OWNERSHIP:
          x->preserve_ownership = on_off;
          break;

        case PRESERVE_LINK:
          x->preserve_links = on_off;
          break;

        case PRESERVE_CONTEXT:
          x->preserve_security_context = on_off;
          x->require_preserve_context = on_off;
          break;

        case PRESERVE_XATTR:
          x->preserve_xattr = on_off;
          x->require_preserve_xattr = on_off;
          break;

        case PRESERVE_ALL:
          x->preserve_mode = on_off;
          x->preserve_timestamps = on_off;
          x->preserve_ownership = on_off;
          x->preserve_links = on_off;
          if (selinux_enabled)
            x->preserve_security_context = on_off;
          x->preserve_xattr = on_off;
          break;

        default:
          abort ();
        }
      s = comma;
    }
  while (s);

  free (arg_writable);
}

int
main (int argc, char **argv)
{
  int c;
  bool ok;
  bool make_backups = false;
  char *backup_suffix_string;
  char *version_control_string = NULL;
  struct cp_options x;
  bool copy_contents = false;
  char *target_directory = NULL;
  bool no_target_directory = false;

  initialize_main (&argc, &argv);
  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  atexit (close_stdin);

  selinux_enabled = (0 < is_selinux_enabled ());
  cp_option_init (&x);

  /* FIXME: consider not calling getenv for SIMPLE_BACKUP_SUFFIX unless
     we'll actually use backup_suffix_string.  */
  backup_suffix_string = getenv ("SIMPLE_BACKUP_SUFFIX");

  while ((c = getopt_long (argc, argv, "abdfHilLnprst:uvxPRS:T",
                           long_opts, NULL))
         != -1)
    {
      switch (c)
        {
// PZK >
        case BUFFER_SIZE_OPTION:
          x.buffer_size = (int) strtol(optarg, (char **) NULL, 10);
          if (x.buffer_size < 1 || x.buffer_size > 128)
            error (EXIT_FAILURE, 0, _("invalid buffer size"));
          size_t tmp_bs = x.buffer_size;
          size_t new_bs = 1;
          while (tmp_bs >>= 1) new_bs <<= 1;
          if (x.buffer_size != new_bs)
            error(0, 0, _("note: buffer size has been adjusted to %lld"), new_bs);
          x.buffer_size = new_bs * 1024 * 1024;
          break;
        case DIRECT_READ_OPTION:
          x.read_mode = O_DIRECT;
          break;
        case DIRECT_WRITE_OPTION:
          x.write_mode = O_DIRECT;
          break;
        case DOUBLE_BUFFER_OPTION:
          x.double_buffer = true;
          break;
        case LENGTH_OPTION:
          x.length = (int) strtol(optarg, (char **) NULL, 10);
          if (x.length < 1)
            error (EXIT_FAILURE, 0, _("invalid length"));
          break;
        case NO_DIRECT_READ_OPTION:
          x.read_mode = 0;
          break;
        case NO_DIRECT_WRITE_OPTION:
          x.write_mode = 0;
          break;
        case NO_DOUBLE_BUFFER_OPTION:
          x.double_buffer = false;
          break;
        case OFFSET_OPTION:
          x.offset = (int) strtol(optarg, (char **) NULL, 10);
          if (x.offset < 0)
            error (EXIT_FAILURE, 0, _("invalid offset"));
          break;
        case READ_STDIN_OPTION:
          x.read_stdin = true;
          break;
        case SKIP_CHMOD_OPTION:
          x.skip_chmod = true;
          break;
#ifdef POSIX_FADV_DONTNEED
        case FADVISE_READ_OPTION:
          x.fadvise_read = true;
          break;
        case FADVISE_WRITE_OPTION:
          x.fadvise_write = true;
          break;
#endif
#ifdef _OPENMP
        case PRINT_STATS_OPTION:
          x.print_stats = true;
          break;
        case SPLIT_SIZE_OPTION:
          x.split_size = (int) strtol(optarg, (char **) NULL, 10);
          if (x.split_size < 0)
            error (EXIT_FAILURE, 0, _("invalid split size"));
          if (x.split_size > 0) {
            off_t tmp_ss = x.split_size;
            off_t new_ss = 1;
            while (tmp_ss >>= 1) new_ss <<= 1;
            if (x.split_size != new_ss)
              error(0, 0, _("note: split size has been adjusted to %lld"), new_ss);
            x.split_size = new_ss * 1024 * 1024;
          }
          break;
        case THREADS_OPTION:
          x.threads = (int) strtol(optarg, (char **) NULL, 10);
          if (x.threads < 1 || x.threads > 512)
            error (EXIT_FAILURE, 0, _("invalid number of threads"));
          break;
#endif
#if HAVE_LIBLUSTREAPI
        case PRINT_STRIPE_OPTION:
          x.print_stripe = true;
          break;
#endif
#if HAVE_LIBGCRYPT
        case CHECK_TREE_OPTION:
          x.check_tree = true;
          break;
        case HASH_LEAF_SIZE_OPTION:
          x.hash_leaf_size = (int) strtol(optarg, (char **) NULL, 10);
          if (x.hash_leaf_size < 1)
            error (EXIT_FAILURE, 0, _("invalid hash leaf size"));
          off_t tmp_ls = x.hash_leaf_size;
          off_t new_ls = 1;
          while (tmp_ls >>= 1) new_ls <<= 1;
          if (x.hash_leaf_size != new_ls)
            error(0, 0, _("note: hash leaf size has been adjusted to %lld"), new_ls);
          x.hash_leaf_size = new_ls * 1024;
          break;
        case HASH_TYPE_OPTION:
          x.hash_type = -1;
          // 400 taken from libgcrypt benchmark code
          for (int i = 1; i < 400; i++) {
            if (!gcry_md_test_algo(i) &&
                    !strcasecmp(optarg, gcry_md_algo_name(i))) {
                x.hash_type = i;
                break;
            }
          }
          if (x.hash_type < 0) error (EXIT_FAILURE, 0, _("invalid hash type"));
          break;
        case PRINT_HASH_OPTION:
          x.print_hash = true;
          break;
        case STORE_HASH_OPTION:
          x.store_hash = true;
          break;
#endif
#if HAVE_LIBMPI && defined(_OPENMP)
        case MPI_OPTION:
          x.mpi = true;
          break;
#endif
        case SPARSE_OPTION:
          x.sparse_mode = XARGMATCH ("--sparse", optarg,
                                     sparse_type_string, sparse_type);
          break;

        case REFLINK_OPTION:
          if (optarg == NULL)
            x.reflink_mode = REFLINK_ALWAYS;
          else
            x.reflink_mode = XARGMATCH ("--reflink", optarg,
                                       reflink_type_string, reflink_type);
          break;

        case 'a':		/* Like -dR --preserve=all with reduced failure diagnostics. */
          x.dereference = DEREF_NEVER;
          x.preserve_links = true;
          x.preserve_ownership = true;
          x.preserve_mode = true;
          x.preserve_timestamps = true;
          x.require_preserve = true;
          if (selinux_enabled)
             x.preserve_security_context = true;
          x.preserve_xattr = true;
          x.reduce_diagnostics = true;
          x.recursive = true;
          break;

        case 'b':
          make_backups = true;
          if (optarg)
            version_control_string = optarg;
          break;

        case COPY_CONTENTS_OPTION:
          copy_contents = true;
          break;

        case 'd':
          x.preserve_links = true;
          x.dereference = DEREF_NEVER;
          break;

        case 'f':
          x.unlink_dest_after_failed_open = true;
          break;

        case 'H':
          x.dereference = DEREF_COMMAND_LINE_ARGUMENTS;
          break;

        case 'i':
          x.interactive = I_ASK_USER;
          break;

        case 'l':
          x.hard_link = true;
          break;

        case 'L':
          x.dereference = DEREF_ALWAYS;
          break;

        case 'n':
          x.interactive = I_ALWAYS_NO;
          break;

        case 'P':
          x.dereference = DEREF_NEVER;
          break;

        case NO_PRESERVE_ATTRIBUTES_OPTION:
          decode_preserve_arg (optarg, &x, false);
          break;

        case PRESERVE_ATTRIBUTES_OPTION:
          if (optarg == NULL)
            {
              /* Fall through to the case for `p' below.  */
            }
          else
            {
              decode_preserve_arg (optarg, &x, true);
              x.require_preserve = true;
              break;
            }

        case 'p':
          x.preserve_ownership = true;
          x.preserve_mode = true;
          x.preserve_timestamps = true;
          x.require_preserve = true;
          break;

        case PARENTS_OPTION:
          parents_option = true;
          break;

        case 'r':
        case 'R':
          x.recursive = true;
          break;

        case UNLINK_DEST_BEFORE_OPENING:
          x.unlink_dest_before_opening = true;
          break;

        case STRIP_TRAILING_SLASHES_OPTION:
          remove_trailing_slashes = true;
          break;

        case 's':
          x.symbolic_link = true;
          break;

        case 't':
          if (target_directory)
            error (EXIT_FAILURE, 0,
                   _("multiple target directories specified"));
          else
            {
              struct stat st;
              if (stat (optarg, &st) != 0)
                error (EXIT_FAILURE, errno, _("accessing %s"), quote (optarg));
              if (! S_ISDIR (st.st_mode))
                error (EXIT_FAILURE, 0, _("target %s is not a directory"),
                       quote (optarg));
            }
          target_directory = optarg;
          break;

        case 'T':
          no_target_directory = true;
          break;

        case 'u':
          x.update = true;
          break;

        case 'v':
          x.verbose = true;
          break;

        case 'x':
          x.one_file_system = true;
          break;

        case 'S':
          make_backups = true;
          backup_suffix_string = optarg;
          break;

        case_GETOPT_HELP_CHAR;

        case_GETOPT_VERSION_CHAR (PROGRAM_NAME, AUTHORS);

        default:
          usage (EXIT_FAILURE);
        }
    }

  if (x.hard_link & x.symbolic_link)
    {
      error (0, 0, _("cannot make both hard and symbolic links"));
      usage (EXIT_FAILURE);
    }

  if (make_backups && x.interactive == I_ALWAYS_NO)
    {
      error (0, 0,
             _("options --backup and --no-clobber are mutually exclusive"));
      usage (EXIT_FAILURE);
    }

  if (x.reflink_mode == REFLINK_ALWAYS && x.sparse_mode != SPARSE_AUTO)
    {
      error (0, 0, _("--reflink can be used only with --sparse=auto"));
      usage (EXIT_FAILURE);
    }

  if (backup_suffix_string)
    simple_backup_suffix = xstrdup (backup_suffix_string);

  x.backup_type = (make_backups
                   ? xget_version (_("backup type"),
                                   version_control_string)
                   : no_backups);

  if (x.dereference == DEREF_UNDEFINED)
    {
      if (x.recursive)
        /* This is compatible with FreeBSD.  */
        x.dereference = DEREF_NEVER;
      else
        x.dereference = DEREF_ALWAYS;
    }

  if (x.recursive)
    x.copy_as_regular = copy_contents;

  /* If --force (-f) was specified and we're in link-creation mode,
     first remove any existing destination file.  */
  if (x.unlink_dest_after_failed_open & (x.hard_link | x.symbolic_link))
    x.unlink_dest_before_opening = true;

  if (x.preserve_security_context)
    {
      if (!selinux_enabled)
        error (EXIT_FAILURE, 0,
               _("cannot preserve security context "
                 "without an SELinux-enabled kernel"));
    }

#if !USE_XATTR
  if (x.require_preserve_xattr)
    error (EXIT_FAILURE, 0, _("cannot preserve extended attributes, cp is "
                              "built without xattr support"));
#endif

  /* Allocate space for remembering copied and created files.  */

  hash_init ();

// PZK >
  if (target_directory && x.read_stdin)
    error (EXIT_FAILURE, 0, _("cannot use --target-directory (-t) with --read_stdin"));
  if (x.read_mode && x.fadvise_read) {
#if DEFAULT_DIRECT_READ
    x.read_mode = 0;
#else
    error(0, 0, _("note: --fadvise-read disabled in favor of --direct-read"));
    x.fadvise_read = false;
#endif
  }
  if (x.write_mode && x.fadvise_write) {
#if DEFAULT_DIRECT_WRITE
    x.write_mode = 0;
#else
    error(0, 0, _("note: --fadvise-write disabled in favor of --direct-write"));
    x.fadvise_write = false;
#endif
  }
#if HAVE_LIBGCRYPT
  //TODO: temporarily disable options that excercise filesystem bugs
  if (x.store_hash) {
    error(0, 0, _("note: hash stores have been temporarily disabled in this version"));
    x.store_hash = false;
  }
  //TODO: reenable above when filesystem bugs are fixed
  if ((x.offset || x.length) && x.store_hash)
    error(EXIT_FAILURE, 0, _("cannot store hash during partial file copy"));
  if (x.split_size > 0 && x.split_size < x.buffer_size) {
    error(0, 0, _("note: split size has been adjusted to the buffer size"));
    x.split_size = x.buffer_size;
  }
  if (x.split_size > 0 && x.split_size < x.hash_leaf_size) {
    error(0, 0, _("note: hash leaf size has been adjusted to the split size"));
    x.hash_leaf_size = x.split_size;
  }
  if (!x.hash_leaf_size) {
    error(0, 0, _("note: hash leaf size has been adjusted to 1GiB"));
    x.hash_leaf_size = 1024 * 1024 * 1024;
  }
  x.hash_size = gcry_md_get_algo_dlen(x.hash_type);
#endif
#ifndef _OPENMP
  x.threads = 0;
#endif

  ok = do_copy (argc - optind, argv + optind,
                target_directory, no_target_directory, &x);

  forget_all ();

  exit (ok ? EXIT_SUCCESS : EXIT_FAILURE);
}


/* core functions for copying files and directories

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

/* Extracted from cp.c and librarified by Jim Meyering.
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

#ifndef COPY_H
# define COPY_H

# include <stdbool.h>
# include "hash.h"

// PZK >
# include <stdlib.h>
# include <sys/stat.h>
# include <time.h>
# include <netinet/in.h>

# include "backupfile.h"
# include "mcore-omp.h"
// < PZK

/* Control creation of sparse files (files with holes).  */
enum Sparse_type
{
  SPARSE_UNUSED,

  /* Never create holes in DEST.  */
  SPARSE_NEVER,

  /* This is the default.  Use a crude (and sometimes inaccurate)
     heuristic to determine if SOURCE has holes.  If so, try to create
     holes in DEST.  */
  SPARSE_AUTO,

  /* For every sufficiently long sequence of bytes in SOURCE, try to
     create a corresponding hole in DEST.  There is a performance penalty
     here because CP has to search for holes in SRC.  But if the holes are
     big enough, that penalty can be offset by the decrease in the amount
     of data written to disk.   */
  SPARSE_ALWAYS
};

/* Control creation of COW files.  */
enum Reflink_type
{
  /* Default to a standard copy.  */
  REFLINK_NEVER,

  /* Try a COW copy and fall back to a standard copy.  */
  REFLINK_AUTO,

  /* Require a COW copy and fail if not available.  */
  REFLINK_ALWAYS
};

/* This type is used to help mv (via copy.c) distinguish these cases.  */
enum Interactive
{
  I_ALWAYS_YES = 1,
  I_ALWAYS_NO,
  I_ASK_USER,
  I_UNSPECIFIED
};

/* How to handle symbolic links.  */
enum Dereference_symlink
{
  DEREF_UNDEFINED = 1,

  /* Copy the symbolic link itself.  -P  */
  DEREF_NEVER,

  /* If the symbolic is a command line argument, then copy
     its referent.  Otherwise, copy the symbolic link itself.  -H  */
  DEREF_COMMAND_LINE_ARGUMENTS,

  /* Copy the referent of the symbolic link.  -L  */
  DEREF_ALWAYS
};

# define VALID_SPARSE_MODE(Mode)	\
  ((Mode) == SPARSE_NEVER		\
   || (Mode) == SPARSE_AUTO		\
   || (Mode) == SPARSE_ALWAYS)

# define VALID_REFLINK_MODE(Mode)	\
  ((Mode) == REFLINK_NEVER		\
   || (Mode) == REFLINK_AUTO		\
   || (Mode) == REFLINK_ALWAYS)

/* These options control how files are copied by at least the
   following programs: mv (when rename doesn't work), cp, install.
   So, if you add a new member, be sure to initialize it in
   mv.c, cp.c, and install.c.  */
struct cp_options
{
// PZK >
  size_t buffer_size;
  bool check_tree;
  bool double_buffer;
  bool fadvise_read;
  bool fadvise_write;
  off_t hash_leaf_size;
  unsigned int hash_size;
  long long *hash_stat_tasks;
  int hash_type;
  off_t length;
  in_port_t listen_port;
  struct addrinfo *mgr_ai;
  char *mg_file;
  in_port_t mgr_port;
  bool mpi;
  off_t offset;
  omp_q_t *open_q;
  char *pass;
  bool print_hash;
  bool print_stats;
  bool print_stripe;
  char *pw_file;
  int read_mode;
  bool read_stdin;
  omp_q_t *send_q;
  bool skip_chmod;
  off_t split_size;
  bool store_hash;
  omp_q_t *task_q;
  int threads;
  char *user;
  int write_mode;
// < PZK

  enum backup_type backup_type;

  /* How to handle symlinks in the source.  */
  enum Dereference_symlink dereference;

  /* This value is used to determine whether to prompt before removing
     each existing destination file.  It works differently depending on
     whether move_mode is set.  See code/comments in copy.c.  */
  enum Interactive interactive;

  /* Control creation of sparse files.  */
  enum Sparse_type sparse_mode;

  /* Set the mode of the destination file to exactly this value
     if SET_MODE is nonzero.  */
  mode_t mode;

  /* If true, copy all files except (directories and, if not dereferencing
     them, symbolic links,) as if they were regular files.  */
  bool copy_as_regular;

  /* If true, remove each existing destination nondirectory before
     trying to open it.  */
  bool unlink_dest_before_opening;

  /* If true, first try to open each existing destination nondirectory,
     then, if the open fails, unlink and try again.
     This option must be set for `cp -f', in case the destination file
     exists when the open is attempted.  It is irrelevant to `mv' since
     any destination is sure to be removed before the open.  */
  bool unlink_dest_after_failed_open;

  /* If true, create hard links instead of copying files.
     Create destination directories as usual. */
  bool hard_link;

  /* If true, rather than copying, first attempt to use rename.
     If that fails, then resort to copying.  */
  bool move_mode;

  /* Whether this process has appropriate privileges to chown a file
     whose owner is not the effective user ID.  */
  bool chown_privileges;

  /* Whether this process has appropriate privileges to do the
     following operations on a file even when it is owned by some
     other user: set the file's atime, mtime, mode, or ACL; remove or
     rename an entry in the file even though it is a sticky directory,
     or to mount on the file.  */
  bool owner_privileges;

  /* If true, when copying recursively, skip any subdirectories that are
     on different file systems from the one we started on.  */
  bool one_file_system;

  /* If true, attempt to give the copies the original files' permissions,
     owner, group, and timestamps. */
  bool preserve_ownership;
  bool preserve_mode;
  bool preserve_timestamps;

  /* Enabled for mv, and for cp by the --preserve=links option.
     If true, attempt to preserve in the destination files any
     logical hard links between the source files.  If used with cp's
     --no-dereference option, and copying two hard-linked files,
     the two corresponding destination files will also be hard linked.

     If used with cp's --dereference (-L) option, then, as that option implies,
     hard links are *not* preserved.  However, when copying a file F and
     a symlink S to F, the resulting S and F in the destination directory
     will be hard links to the same file (a copy of F).  */
  bool preserve_links;

  /* If true and any of the above (for preserve) file attributes cannot
     be applied to a destination file, treat it as a failure and return
     nonzero immediately.  E.g. for cp -p this must be true, for mv it
     must be false.  */
  bool require_preserve;

  /* If true, attempt to preserve the SELinux security context, too.
     Set this only if the kernel is SELinux enabled.  */
  bool preserve_security_context;

  /* Useful only when preserve_security_context is true.
     If true, a failed attempt to preserve a file's security context
     propagates failure "out" to the caller.  If false, a failure to
     preserve a file's security context does not change the invoking
     application's exit status.  Give diagnostics for failed syscalls
     regardless of this setting.  For example, with "cp --preserve=context"
     this flag is "true", while with "cp -a", it is false.  That means
     "cp -a" attempts to preserve any security context, but does not
     fail if it is unable to do so.  */
  bool require_preserve_context;

  /* If true, attempt to preserve extended attributes using libattr.
     Ignored if coreutils are compiled without xattr support. */
  bool preserve_xattr;

  /* Useful only when preserve_xattr is true.
     If true, a failed attempt to preserve file's extended attributes
     propagates failure "out" to the caller.  If false, a failure to
     preserve file's extended attributes does not change the invoking
     application's exit status.  Give diagnostics for failed syscalls
     regardless of this setting.  For example, with "cp --preserve=xattr"
     this flag is "true", while with "cp --preserve=all", it is false. */
  bool require_preserve_xattr;

  /* Used as difference boolean between cp -a and cp -dR --preserve=all.
     If true, non-mandatory failure diagnostics are not displayed. This
     should prevent poluting cp -a output.
   */
  bool reduce_diagnostics;

  /* If true, copy directories recursively and copy special files
     as themselves rather than copying their contents. */
  bool recursive;

  /* If true, set file mode to value of MODE.  Otherwise,
     set it based on current umask modified by UMASK_KILL.  */
  bool set_mode;

  /* If true, create symbolic links instead of copying files.
     Create destination directories as usual. */
  bool symbolic_link;

  /* If true, do not copy a nondirectory that has an existing destination
     with the same or newer modification time. */
  bool update;

  /* If true, display the names of the files before copying them. */
  bool verbose;

  /* If true, stdin is a tty.  */
  bool stdin_tty;

  /* If true, open a dangling destination symlink when not in move_mode.
     Otherwise, copy_reg gives a diagnostic (it refuses to write through
     such a symlink) and returns false.  */
  bool open_dangling_dest_symlink;

  /* Control creation of COW files.  */
  enum Reflink_type reflink_mode;

  /* This is a set of destination name/inode/dev triples.  Each such triple
     represents a file we have created corresponding to a source file name
     that was specified on the command line.  Use it to avoid clobbering
     source files in commands like this:
       rm -rf a b c; mkdir a b c; touch a/f b/f; mv a/f b/f c
     For now, it protects only regular files when copying (i.e. not renaming).
     When renaming, it protects all non-directories.
     Use dest_info_init to initialize it, or set it to NULL to disable
     this feature.  */
  Hash_table *dest_info;

  /* FIXME */
  Hash_table *src_info;
};

# define XSTAT(X, Src_name, Src_sb) \
  ((X)->dereference == DEREF_NEVER \
   ? lstat (Src_name, Src_sb) \
   : stat (Src_name, Src_sb))

/* Arrange to make rename calls go through the wrapper function
   on systems with a rename function that fails for a source file name
   specified with a trailing slash.  */
# if RENAME_TRAILING_SLASH_BUG
int rpl_rename (const char *, const char *);
#  undef rename
#  define rename rpl_rename
# endif

bool copy (char const *src_name, char const *dst_name,
           bool nonexistent_dst, const struct cp_options *options,
           bool *copy_into_self, bool *rename_succeeded);

void dest_info_init (struct cp_options *);
void src_info_init (struct cp_options *);

void cp_options_default (struct cp_options *);
bool chown_failure_ok (struct cp_options const *);
mode_t cached_umask (void);

// PZK >
typedef struct {
    double copy_time;
    int dest_desc;
    size_t dst_blksize;
    mode_t dst_mode;
    char *dst_name;
    unsigned char *hash_stack;
    bool partial;
    size_t nsplits;
    double read_time;
    int source_desc;
    size_t split;
    struct timespec src_atime;
    struct timespec src_mtime;
    char *src_name;
    off_t start_offset;
    off_t stop_offset;
    double write_time;
} copy_reg_t;

bool copy_reg_task(copy_reg_t *crt, struct cp_options *co);
// < PZK

#endif

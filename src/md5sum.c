/* Compute MD5, SHA1, SHA224, SHA256, SHA384 or SHA512 checksum of files or strings

   Copyright 2010 United States Government National Aeronautics and
   Space Administration (NASA).  No copyright is claimed in the United
   States under Title 17, U.S. Code.  All Other Rights Reserved.

   Copyright (C) 1995-2009 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License Version 3 with
   Additional Terms below (per Section 7 of GPL V3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Ulrich Drepper <drepper@gnu.ai.mit.edu>.
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

#include <config.h>

#include <getopt.h>
#include <sys/types.h>

#include "system.h"

#if HASH_ALGO_MD5
# include "md5.h"
#endif
#if HASH_ALGO_SHA1
# include "sha1.h"
#endif
#if HASH_ALGO_SHA256 || HASH_ALGO_SHA224
# include "sha256.h"
#endif
#if HASH_ALGO_SHA512 || HASH_ALGO_SHA384
# include "sha512.h"
#endif
#include "error.h"
#include "stdio--.h"
#include "xfreopen.h"

// PZK >
#include "buffer-lcm.h"
#include "mcore.h"
#include "mkancesdirs.h"
#include "quote.h"
#include "savewd.h"
#include <aio.h>
#include <ctype.h>

#if HAVE_LIBGCRYPT
# include <gcrypt.h>
# ifdef _OPENMP
#  include <pthread.h>
GCRY_THREAD_OPTION_PTHREAD_IMPL;
# endif
#endif

#if HAVE_LIBMPI && defined(_OPENMP)
# include "mpi.h"
#endif
#undef HAVE_LIBGNUTLS
#if HAVE_LIBGNUTLS && defined(_OPENMP)
# include <arpa/inet.h>
# include <gnutls/gnutls.h>
# include <gnutls/extra.h>
# include <netdb.h>
# include <poll.h>
# include <pthread.h>
# include <pwd.h>
# include <sys/socket.h>
#endif
// < PZK

/* The official name of this program (e.g., no `g' prefix).  */
#if HASH_ALGO_MD5
# define PROGRAM_NAME "msum 1.76.4"
# define DIGEST_TYPE_STRING "MD5"
# define DIGEST_STREAM md5_stream
# define DIGEST_BITS 128
# define DIGEST_REFERENCE "RFC 1321"
# define DIGEST_ALIGN 4
#elif HASH_ALGO_SHA1
# define PROGRAM_NAME "sha1sum"
# define DIGEST_TYPE_STRING "SHA1"
# define DIGEST_STREAM sha1_stream
# define DIGEST_BITS 160
# define DIGEST_REFERENCE "FIPS-180-1"
# define DIGEST_ALIGN 4
#elif HASH_ALGO_SHA256
# define PROGRAM_NAME "sha256sum"
# define DIGEST_TYPE_STRING "SHA256"
# define DIGEST_STREAM sha256_stream
# define DIGEST_BITS 256
# define DIGEST_REFERENCE "FIPS-180-2"
# define DIGEST_ALIGN 4
#elif HASH_ALGO_SHA224
# define PROGRAM_NAME "sha224sum"
# define DIGEST_TYPE_STRING "SHA224"
# define DIGEST_STREAM sha224_stream
# define DIGEST_BITS 224
# define DIGEST_REFERENCE "RFC 3874"
# define DIGEST_ALIGN 4
#elif HASH_ALGO_SHA512
# define PROGRAM_NAME "sha512sum"
# define DIGEST_TYPE_STRING "SHA512"
# define DIGEST_STREAM sha512_stream
# define DIGEST_BITS 512
# define DIGEST_REFERENCE "FIPS-180-2"
# define DIGEST_ALIGN 8
#elif HASH_ALGO_SHA384
# define PROGRAM_NAME "sha384sum"
# define DIGEST_TYPE_STRING "SHA384"
# define DIGEST_STREAM sha384_stream
# define DIGEST_BITS 384
# define DIGEST_REFERENCE "FIPS-180-2"
# define DIGEST_ALIGN 8
#else
# error "Can't decide which hash algorithm to compile."
#endif

#define DIGEST_HEX_BYTES (DIGEST_BITS / 4)
#define DIGEST_BIN_BYTES (DIGEST_BITS / 8)

// PZK >
#define AUTHORS \
  proper_name ("Ulrich Drepper"), \
  proper_name ("Scott Miller"), \
  proper_name ("David Madore"), \
  proper_name ("Paul Kolano")

#ifndef DEFAULT_BUFFER_SIZE
# define DEFAULT_BUFFER_SIZE 4
#endif
#ifndef DEFAULT_DIRECT_READ
# define DEFAULT_DIRECT_READ 0
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

/* The minimum length of a valid digest line.  This length does
   not include any newline character at the end of a line.  */
#define MIN_DIGEST_LINE_LENGTH \
  (DIGEST_HEX_BYTES /* length of hexadecimal message digest */ \
   + 2 /* blank and binary indicator */ \
   + 1 /* minimum filename length */ )

/* True if any of the files read were the standard input. */
static bool have_read_stdin;

/* The minimum length of a valid checksum line for the selected algorithm.  */
static size_t min_digest_line_length;

/* Set to the length of a digest hex string for the selected algorithm.  */
static size_t digest_hex_bytes;

/* With --check, don't generate any output.
   The exit code indicates success or failure.  */
static bool status_only = false;

/* With --check, print a message to standard error warning about each
   improperly formatted checksum line.  */
static bool warn = false;

/* With --check, suppress the "OK" printed for each verified file.  */
static bool quiet = false;

/* For long options that have no equivalent short option, use a
   non-character as a pseudo short option, starting with CHAR_MAX + 1.  */
enum
{
  STATUS_OPTION = CHAR_MAX + 1,
// PZK >
  BUFFER_SIZE_OPTION,
  DIRECT_READ_OPTION,
  DOUBLE_BUFFER_OPTION,
  LENGTH_OPTION,
  NO_DIRECT_READ_OPTION,
  NO_DOUBLE_BUFFER_OPTION,
  OFFSET_OPTION,
  READ_STDIN_OPTION,
#ifdef POSIX_FADV_DONTNEED
  FADVISE_READ_OPTION,
#endif
#ifdef _OPENMP
  PRINT_STATS_OPTION,
  SPLIT_SIZE_OPTION,
  THREADS_OPTION,
#endif
#if HAVE_LIBGCRYPT
  CHECK_TREE_OPTION,
  HASH_LEAF_SIZE_OPTION,
  HASH_TYPE_OPTION,
  STORE_HASH_OPTION,
#endif
#if HAVE_LIBMPI && defined(_OPENMP)
  MPI_OPTION,
#endif
#if HAVE_LIBGNUTLS && defined(_OPENMP)
  LISTEN_PORT_OPTION,
  MANAGER_HOST_OPTION,
  MANAGER_PORT_OPTION,
  PASSWORD_FILE_OPTION,
#endif
// < PZK
  QUIET_OPTION
};

static struct option const long_options[] =
{
// PZK >
  {"buffer-size", required_argument, NULL, BUFFER_SIZE_OPTION},
  {"direct-read", no_argument, NULL, DIRECT_READ_OPTION},
  {"double-buffer", no_argument, NULL, DOUBLE_BUFFER_OPTION},
  {"length", required_argument, NULL, LENGTH_OPTION},
  {"no-direct-read", no_argument, NULL, NO_DIRECT_READ_OPTION},
  {"no-double-buffer", no_argument, NULL, NO_DOUBLE_BUFFER_OPTION},
  {"offset", required_argument, NULL, OFFSET_OPTION},
  {"read-stdin", no_argument, NULL, READ_STDIN_OPTION},
#ifdef POSIX_FADV_DONTNEED
  {"fadvise-read", no_argument, NULL, FADVISE_READ_OPTION},
#endif
#ifdef _OPENMP
  {"print-stats", no_argument, NULL, PRINT_STATS_OPTION},
  {"split-size", required_argument, NULL, SPLIT_SIZE_OPTION},
  {"threads", required_argument, NULL, THREADS_OPTION},
#endif
#if HAVE_LIBGCRYPT
  {"check-tree", no_argument, NULL, CHECK_TREE_OPTION},
  {"hash-leaf-size", required_argument, NULL, HASH_LEAF_SIZE_OPTION},
  {"hash-type", required_argument, NULL, HASH_TYPE_OPTION},
  {"store-hash", no_argument, NULL, STORE_HASH_OPTION},
#endif
#if HAVE_LIBMPI && defined(_OPENMP)
  {"mpi", no_argument, NULL, MPI_OPTION},
#endif
#if HAVE_LIBGNUTLS
  {"listen-port", required_argument, NULL, LISTEN_PORT_OPTION},
  {"manager-host", required_argument, NULL, MANAGER_HOST_OPTION},
  {"manager-port", required_argument, NULL, MANAGER_PORT_OPTION},
  {"password-file", required_argument, NULL, PASSWORD_FILE_OPTION},
#endif
// < PZK
  { "binary", no_argument, NULL, 'b' },
  { "check", no_argument, NULL, 'c' },
  { "quiet", no_argument, NULL, QUIET_OPTION },
  { "status", no_argument, NULL, STATUS_OPTION },
  { "text", no_argument, NULL, 't' },
  { "warn", no_argument, NULL, 'w' },
  { GETOPT_HELP_OPTION_DECL },
  { GETOPT_VERSION_OPTION_DECL },
  { NULL, 0, NULL, 0 }
};

// PZK >
#define sum_options cp_options
#define sum_task_t copy_reg_t
#define hash_time write_time
#define sum_time copy_time
#define hash_check dst_name

static void
sum_option_init (struct sum_options *x)
{
  x->buffer_size = DEFAULT_BUFFER_SIZE * 1024 * 1024;
  x->check_tree = false;
#if DEFAULT_DOUBLE_BUFFER
  x->double_buffer = true;
#else
  x->double_buffer = false;
#endif
  x->fadvise_read = false;
  x->hash_size = 0;
  x->hash_stat_tasks = xcalloc(1, sizeof(long long));
#if HAVE_LIBGCRYPT
  x->hash_type = DEFAULT_HASH_TYPE;
#endif
  x->length = 0;
  x->listen_port = 0;
  x->mg_file = NULL;
  x->mgr_ai = NULL;
  x->mgr_port = 0;
  x->mpi = false;
  x->offset = 0;
  x->pass = NULL;
  x->print_stats = false;
  x->pw_file = 0;
#if DEFAULT_DIRECT_READ
  x->read_mode = O_DIRECT;
#else
  x->read_mode = 0;
#endif
  x->read_stdin = false;
  x->split_size = DEFAULT_SPLIT_SIZE * 1024 * 1024;
  x->hash_leaf_size = x->split_size; // this must follow split_size
  x->store_hash = false;
  x->task_q = NULL;
  x->threads = DEFAULT_THREADS;
  x->user = NULL;
}

extern bool
sum_task(sum_task_t *stt, struct sum_options *so)
{
  char *buf[2];
  char *buf_alloc[2];
  buf_alloc[0] = NULL;
  buf_alloc[1] = NULL;
  struct stat src_open_sb;
  bool return_val = true;

#if HAVE_LIBGCRYPT
  hash_tree_t htt;
#endif

  int source_desc =
    open(stt->src_name, O_RDONLY | O_BINARY | so->read_mode);
  if (source_desc < 0)
    error(0, errno, _("warning: unable to open %s for read"), quote(stt->src_name));
  if (lseek(source_desc, stt->start_offset, SEEK_SET) < 0)
    error(0, errno, _("warning: unable to seek in %s"), quote(stt->src_name));
  //TODO: additional error handling if can't open or seek?

  if (fstat (source_desc, &src_open_sb) != 0)
    {
      error (0, errno, _("cannot fstat %s"), quote (stt->src_name));
      return_val = false;
      goto task_close_src_and_dst_desc;
    }

  typedef uintptr_t word;
  off_t n_read_total = 0;

  /* Choose a suitable buffer size; it may be adjusted later.  */
  size_t buf_alignment = lcm (getpagesize (), sizeof (word));
  size_t buf_alignment_slop = sizeof (word) + buf_alignment - 1;
  size_t buf_size = stt->dst_blksize;

  /* Compute the least common multiple of the input and output
     buffer sizes, adjusting for outlandish values.  */
  size_t blcm_max = MIN (SIZE_MAX, SSIZE_MAX) - buf_alignment_slop;
  size_t blcm = buffer_lcm (io_blksize (src_open_sb), buf_size,
                                blcm_max);
  blcm = so->buffer_size;
  if (so->read_mode)
    blcm = buffer_lcm (blcm, 512, blcm_max);

  /* Do not bother with a buffer larger than the input file, plus one
     byte to make sure the file has not grown while reading it.  */
  if (S_ISREG (src_open_sb.st_mode) && src_open_sb.st_size < buf_size)
    buf_size = src_open_sb.st_size + 1;

  /* However, stick with a block size that is a positive multiple of
     blcm, overriding the above adjustments.  Watch out for
     overflow.  */
  buf_size += blcm - 1;
  buf_size -= buf_size % blcm;
  if (buf_size == 0 || blcm_max < buf_size)
    buf_size = blcm;

  /* Make a buffer with space for a sentinel at the end.  */
  buf_alloc[0] = xmalloc (buf_size + buf_alignment_slop);
  buf[0] = ptr_align (buf_alloc[0], buf_alignment);
  if (so->double_buffer) {
    buf_alloc[1] = xmalloc (buf_size + buf_alignment_slop);
    buf[1] = ptr_align (buf_alloc[1], buf_alignment);
  }

#if HAVE_LIBGCRYPT
  gcry_md_hd_t ctx;
  gcry_md_open(&ctx, so->hash_type, 0);
  if (stt->nsplits > 1) {
    htt.n_hash_total = 0;
    htt.hash_ctx = &ctx;
    htt.hash_ctx_len = 0;
//TODO:    if (so->store_hash) htt.xattr = xmalloc(ATTR_MAX_VALUELEN);
    htt.xattr_len = 0;
    //TODO: this is wrong since there is no writable dst
    //htt.fd = stt->dest_desc;
    htt.fd = -1;
    htt.stack_len = 0;

    // compute approximate height of split sub-tree
    off_t leafs = (stt->stop_offset - stt->start_offset) /
        so->hash_leaf_size + 1;
    ssize_t n = 1;
    while (leafs >>= 1) n++;
    // stack needs space for at most height of tree hashes
    htt.stack = xmalloc(n * so->hash_size);
  }
#endif

  struct timespec rts[2], hts[2];
  struct aiocb aio;
  struct aiocb *aiol[1];
  aiol[0] = NULL;
  int aio_buf = 0;

  for (;;)
    {
      if (stt->nsplits > 1 &&
            n_read_total >= stt->stop_offset - stt->start_offset) break;

      ssize_t n_read;
      if (aiol[0] != NULL) {
        // this will be skipped during the first double buffer iteration
        aio_suspend(aiol, 1, NULL);
        n_read = aio_return(aiol[0]);
      } else {
        if (so->read_mode &&
                stt->stop_offset - stt->start_offset - n_read_total < buf_size) {
            // turn off direct i/o if going to read last unaligned block
            // since it causes problems for some file systems
            int old_flags = fcntl(source_desc, F_GETFL);
            if (fcntl(source_desc, F_SETFL, old_flags & ~O_DIRECT) != 0)
                error(0, errno, _("failed to turn off O_DIRECT: %s"),
                    quote (stt->src_name));
        }
 
        if (so->print_stats) clock_gettime(CLOCK_REALTIME, &rts[0]);
        n_read = read (source_desc, buf[aio_buf],
          MIN(buf_size, stt->stop_offset - stt->start_offset -
            n_read_total));
      }

      if (so->print_stats) {
        clock_gettime(CLOCK_REALTIME, &rts[1]);
        stt->read_time += (double) (
            (double) rts[1].tv_sec + (double) rts[1].tv_nsec / (double) 1.0e9 -
            (double) rts[0].tv_sec - (double) rts[0].tv_nsec / (double) 1.0e9);
      }

      if (n_read < 0)
        {
#ifdef EINTR
          if (errno == EINTR)
            continue;
#endif
          error (0, errno, _("reading %s"), quote (stt->src_name));
          return_val = false;
          goto task_close_src_and_dst_desc;
        }
      if (n_read == 0)
        break;

#ifdef POSIX_FADV_DONTNEED
      if (so->fadvise_read) {
        // indicate done with read data
        posix_fadvise(source_desc, stt->start_offset + n_read_total,
            n_read, POSIX_FADV_DONTNEED);
      }
#endif

      n_read_total += n_read;

      if (so->double_buffer) {
        if (so->read_mode &&
                stt->stop_offset - stt->start_offset - n_read_total < buf_size) {
            // turn off direct i/o if going to read last unaligned block
            // since it causes problems for some file systems
            int old_flags = fcntl(source_desc, F_GETFL);
            if (fcntl(source_desc, F_SETFL, old_flags & ~O_DIRECT) != 0)
                error(0, errno, _("failed to turn off O_DIRECT: %s"),
                    quote (stt->src_name));
        }
 
        if (so->print_stats) clock_gettime(CLOCK_REALTIME, &rts[0]);
        memset(&aio, 0, sizeof(struct aiocb));
        aio.aio_fildes = source_desc;
        aio.aio_offset = stt->start_offset + n_read_total;
        aio.aio_buf = buf[!aio_buf];
        aio.aio_nbytes = MIN(buf_size,
            stt->stop_offset - stt->start_offset - n_read_total);
        aiol[0] = &aio;
        //TODO: error handling for bad aio_read
        aio_read(&aio);
      }

      if (so->print_stats) clock_gettime(CLOCK_REALTIME, &hts[0]);
#if HAVE_LIBGCRYPT
       //TODO: is st_size right for partial files?
      if (stt->nsplits > 1)
        hash_tree(&htt, stt, so, buf[aio_buf], n_read_total, src_open_sb.st_size);
      else
        gcry_md_write(ctx, buf[aio_buf], n_read);
#endif
      if (so->print_stats) {
        clock_gettime(CLOCK_REALTIME, &hts[1]);
        stt->hash_time += (double) (
            (double) hts[1].tv_sec + (double) hts[1].tv_nsec / (double) 1.0e9 -
            (double) hts[0].tv_sec - (double) hts[0].tv_nsec / (double) 1.0e9);
      }
      if (so->double_buffer) aio_buf = !aio_buf;
    }

task_close_src_and_dst_desc:
  if (close (source_desc) < 0)
    {
      error (0, errno, _("closing %s"), quote (stt->src_name));
      return_val = false;
    }

  free (buf_alloc[0]);
  free (buf_alloc[1]);
  if (!return_val) {
    error (0, 0, _("%s: FAILED open or read"), quote (stt->src_name));
#if HAVE_LIBGCRYPT
  } else {
    // copy final hash onto stt hash stack
    if (stt->nsplits > 1) {
        memcpy(stt->hash_stack, htt.stack, so->hash_size);
    } else {
        memcpy(stt->hash_stack, gcry_md_read(ctx, 0), so->hash_size);
    }
#endif
  }

#if HAVE_LIBGCRYPT
  gcry_md_close(ctx);
  if (stt->nsplits > 1) {
    if (so->store_hash) free(htt.xattr);
    free(htt.stack);
  }
#endif

  return return_val;
}

void print_check(struct sum_options *x, sum_task_t *stt)
{
//TODO: need to make this for general hash length
    static const char bin2hex[] = { '0', '1', '2', '3',
                                    '4', '5', '6', '7',
                                    '8', '9', 'a', 'b',
                                    'c', 'd', 'e', 'f' };
    size_t digest_bin_bytes = digest_hex_bytes / 2;
    size_t cnt, s;
    unsigned char *stack = stt->hash_stack;
    unsigned char *check = stt->hash_check;
    int fail = 0;
    if (!status_only) printf("%s: ", stt->src_name);

    /* Compare generated binary number with text representation
       in check file.  Ignore case of hex digits.  */
    int nsplits = x->check_tree ? stt->nsplits : 1;
    for (s = 0; s < nsplits; s++) {
        for (cnt = 0; cnt < digest_bin_bytes; ++cnt) {
            if (tolower (check[2 * cnt])
                != bin2hex[stack[cnt] >> 4]
                || (tolower (check[2 * cnt + 1])
                    != (bin2hex[stack[cnt] & 0xf])))
            break;
        }
        if (!status_only) {
            if (cnt != digest_bin_bytes) {
                if (!fail) {
                    printf("%s", _("FAILED"));
                    fail = 1;
                }
                if (stt->partial || x->check_tree) {
                    off_t end = stt->start_offset + (s + 1) * x->split_size;
                    if (end > stt->stop_offset) end = stt->stop_offset;
                    printf(",%lld-%lld",
                        stt->start_offset + s * x->split_size, end);
                }
            }
        }
        stack += digest_bin_bytes;
        check += digest_hex_bytes;
    }
/*TODO: do something with this in hash thread
    if (cnt != digest_bin_bytes)
      ++n_mismatched_checksums;
*/
    if (!status_only) {
        if (!quiet && !fail) {
            printf("%s", _("OK"));
            if (stt->partial)
                printf(",%lld-%lld", stt->start_offset, stt->stop_offset);
        }
        if (fail || !quiet) printf("\n");
        fflush (stdout);
    }
}


//TODO: general hash length
void print_hash(struct sum_options *x, sum_task_t *stt)
{
    size_t i;

    // put non-standard output in comments
    if (stt->nsplits > 1 || stt->partial) {
        printf("#mutil#");
        if (stt->partial)
            printf("%lld-%lld", stt->start_offset, stt->stop_offset);
        printf("#");
    }

    /* Output a leading backslash if the file name contains
       a newline or backslash.  */
    if (strchr (stt->src_name, '\n') || strchr (stt->src_name, '\\'))
      putchar ('\\');

    size_t bytes = digest_hex_bytes / 2;
    if (x->check_tree) bytes *= stt->nsplits;
    for (i = 0; i < bytes; ++i)
      printf ("%02x", stt->hash_stack[i]);

    putchar (' ');
/*TODO: do something with this binary stuff
    if (file_is_binary)
      putchar ('*');
    else
*/
      putchar (' ');

    /* Translate each NEWLINE byte to the string, "\\n",
       and each backslash to "\\\\".  */
    for (i = 0; i < strlen (stt->src_name); ++i)
      {
        switch (stt->src_name[i])
          {
          case '\n':
            fputs ("\\n", stdout);
            break;

          case '\\':
            fputs ("\\\\", stdout);
            break;

          default:
            putchar (stt->src_name[i]);
            break;
          }
      }
    putchar ('\n');
}
// < PZK

void
usage (int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
             program_name);
  else
    {
// PZK >
      printf (_("\
Usage: %s [OPTION]... [FILE]...\n\
Print or check checksums.\n\
With no FILE, or when FILE is -, read standard input.\n\
\n\
"),
              program_name);
      fputs (_("Msum-specific options (defaults in brackets):\n"), stdout);
      fprintf (stdout, _("\
      --buffer-size=MBYTES     read/write buffer size [%d]\n"),
        DEFAULT_BUFFER_SIZE);
#if HAVE_LIBGCRYPT
      fputs (_("\
      --check-tree             print/check hash subtrees to pinpoint corruption\n\
"), stdout);
#endif
#if !DEFAULT_DIRECT_READ
      fputs (_("\
      --direct-read            enable use of direct I/O for reads\n\
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
      --length=LEN             hash LEN bytes beginning at --offset\n\
                                 (or 0 if --offset not specified)\n\
"), stdout);
#if HAVE_LIBGNUTLS && defined(_OPENMP)
      fputs (_("\
      --listen-port=PORT       listen on port PORT for requests from\n\
                                 cooperating hosts\n\
      --manager-host=HOST      host name or IP address of management thread\n\
                                 for multi-node/multi-host copies\n\
      --manager-port=PORT      port on which to contact management thread\n\
"), stdout);
#endif
#if HAVE_LIBMPI && defined(_OPENMP)
      fputs (_("\
      --mpi                    enable use of MPI for multi-node checksums\n\
"), stdout);
#endif
#if DEFAULT_DIRECT_READ
      fputs (_("\
      --no-direct-read         disable use of direct I/O for reads\n\
"), stdout);
#endif
#if DEFAULT_DOUBLE_BUFFER
      fputs (_("\
      --no-double-buffer       disable use of double buffering during file I/O\n\
"), stdout);
#endif
      fputs (_("\
      --offset=POS             hash --length bytes beginning at POS\n\
                                 (or to end if --length not specified)\n\
"), stdout);
#if HAVE_LIBGNUTLS && defined(_OPENMP)
      fputs (_("\
      --password-file=FILE     file to use for passwords (will be created\n\
                                 if does not exist)\n\
"), stdout);
#endif
#ifdef _OPENMP
      fprintf (stdout, _("\
      --read-stdin             perform a batch of operations read over stdin\n\
                                 in the form 'FILE RANGES' where FILE must be\n\
                                 a URI-escaped (RFC 3986) file name and RANGES\n\
                                 is zero or more comma-separated ranges of the\n\
                                 form 'START-END' for 0 <= START < END\n\
      --split-size=MBYTES      size to split files for parallelization [%d]\n\
      --threads=NUMBER         number of OpenMP worker threads to use [%d]\n\
\n\
"), DEFAULT_SPLIT_SIZE, DEFAULT_THREADS);
#endif
      fputs (_("Standard options:\n"), stdout);
// < PZK
      if (O_BINARY)
        fputs (_("\
  -b, --binary            read in binary mode (default unless reading tty stdin)\n\
"), stdout);
      else
        fputs (_("\
  -b, --binary            read in binary mode\n\
"), stdout);
// PZK >
      printf (_("\
  -c, --check             read sums from the FILEs and check them\n"));
// < PZK
      if (O_BINARY)
        fputs (_("\
  -t, --text              read in text mode (default if reading tty stdin)\n\
"), stdout);
      else
        fputs (_("\
  -t, --text              read in text mode (default)\n\
"), stdout);
      fputs (_("\
\n\
The following three options are useful only when verifying checksums:\n\
      --quiet             don't print OK for each successfully verified file\n\
      --status            don't output anything, status code shows success\n\
  -w, --warn              warn about improperly formatted checksum lines\n\
\n\
"), stdout);
      fputs (HELP_OPTION_DESCRIPTION, stdout);
      fputs (VERSION_OPTION_DESCRIPTION, stdout);
// PZK >
      printf (_("\
\n\
When checking, the input should be a former output of this program.\n\
The default mode is to print a line with checksum, a character indicating\n\
type (`*' for binary, ` ' for text), and name for each FILE.\n"));
// < PZK
      emit_bug_reporting_address ();
    }

  exit (status);
}

#define ISWHITE(c) ((c) == ' ' || (c) == '\t')

/* Split the checksum string S (of length S_LEN) from a BSD 'md5' or
   'sha1' command into two parts: a hexadecimal digest, and the file
   name.  S is modified.  Return true if successful.  */

static bool
bsd_split_3 (char *s, size_t s_len, unsigned char **hex_digest, char **file_name)
{
  size_t i;

  if (s_len == 0)
    return false;

  *file_name = s;

  /* Find end of filename. The BSD 'md5' and 'sha1' commands do not escape
     filenames, so search backwards for the last ')'. */
  i = s_len - 1;
  while (i && s[i] != ')')
    i--;

  if (s[i] != ')')
    return false;

  s[i++] = '\0';

  while (ISWHITE (s[i]))
    i++;

  if (s[i] != '=')
    return false;

  i++;

  while (ISWHITE (s[i]))
    i++;

  *hex_digest = (unsigned char *) &s[i];
  return true;
}

/* Split the string S (of length S_LEN) into three parts:
   a hexadecimal digest, binary flag, and the file name.
   S is modified.  Return true if successful.  */

// PZK >
//TODO: need to modify this to take different hash sizes into account
// < PZK
static bool
split_3 (char *s, size_t s_len,
         unsigned char **hex_digest, int *binary, char **file_name)
{
  size_t i;
  bool escaped_filename = false;
  size_t algo_name_len;

  i = 0;
  while (ISWHITE (s[i]))
    ++i;

  /* Check for BSD-style checksum line. */
  algo_name_len = strlen (DIGEST_TYPE_STRING);
  if (strncmp (s + i, DIGEST_TYPE_STRING, algo_name_len) == 0)
    {
      if (strncmp (s + i + algo_name_len, " (", 2) == 0)
        {
          *binary = 0;
          return bsd_split_3 (s +      i + algo_name_len + 2,
                              s_len - (i + algo_name_len + 2),
                              hex_digest, file_name);
        }
    }

  /* Ignore this line if it is too short.
     Each line must have at least `min_digest_line_length - 1' (or one more, if
     the first is a backslash) more characters to contain correct message digest
     information.  */
  if (s_len - i < min_digest_line_length + (s[i] == '\\'))
    return false;

  if (s[i] == '\\')
    {
      ++i;
      escaped_filename = true;
    }
  *hex_digest = (unsigned char *) &s[i];

  /* The first field has to be the n-character hexadecimal
     representation of the message digest.  If it is not followed
     immediately by a white space it's an error.  */
  i += digest_hex_bytes;
// PZK >
  //TODO: put this in for checktree
  while (!ISWHITE (s[i]))
    i++;
// < PZK
  if (!ISWHITE (s[i]))
    return false;

  s[i++] = '\0';

  if (s[i] != ' ' && s[i] != '*')
    return false;
  *binary = (s[i++] == '*');

  /* All characters between the type indicator and end of line are
     significant -- that includes leading and trailing white space.  */
  *file_name = &s[i];

  if (escaped_filename)
    {
      /* Translate each `\n' string in the file name to a NEWLINE,
         and each `\\' string to a backslash.  */

      char *dst = &s[i];

      while (i < s_len)
        {
          switch (s[i])
            {
            case '\\':
              if (i == s_len - 1)
                {
                  /* A valid line does not end with a backslash.  */
                  return false;
                }
              ++i;
              switch (s[i++])
                {
                case 'n':
                  *dst++ = '\n';
                  break;
                case '\\':
                  *dst++ = '\\';
                  break;
                default:
                  /* Only `\' or `n' may follow a backslash.  */
                  return false;
                }
              break;

            case '\0':
              /* The file name may not contain a NUL.  */
              return false;
              break;

            default:
              *dst++ = s[i++];
              break;
            }
        }
      *dst = '\0';
    }
  return true;
}

/* Return true if S is a NUL-terminated string of DIGEST_HEX_BYTES hex digits.
   Otherwise, return false.  */
static bool
hex_digits (unsigned char const *s)
{
// PZK >
    //TODO: temporarily set this true until check-tree finalized
    return true;
// < PZK
  unsigned int i;
  for (i = 0; i < digest_hex_bytes; i++)
    {
      if (!isxdigit (*s))
        return false;
      ++s;
    }
  return *s == '\0';
}

/* An interface to the function, DIGEST_STREAM.
   Operate on FILENAME (it may be "-").

   *BINARY indicates whether the file is binary.  BINARY < 0 means it
   depends on whether binary mode makes any difference and the file is
   a terminal; in that case, clear *BINARY if the file was treated as
   text because it was a terminal.

   Put the checksum in *BIN_RESULT, which must be properly aligned.
   Return true if successful.  */

static bool
// PZK >
digest_file (struct sum_options *x, unsigned char *h_check,
    const char *filename, int *binary, unsigned char *bin_result)
// < PZK
{
  FILE *fp;
  int err;
  bool is_stdin = STREQ (filename, "-");

// PZK >
#if HAVE_LIBGCRYPT && defined(_OPENMP)
  if (is_stdin) goto do_stdin;

  struct stat src_sb;
  if (stat (filename, &src_sb) != 0) {
      error (0, errno, _("cannot stat %s"), quote (filename));
      return false;
  }

  if (!S_ISREG(src_sb.st_mode)) {
      error (0, 0, _("%s: Is not a regular file"), quote (filename));
      return false;
  }

//TODO:  do something with binary?  why should that matter?
  off_t pos = 0;
  if (x->offset && x->offset > src_sb.st_size) pos = src_sb.st_size;
  else if (x->offset) pos = x->offset;
  off_t end = src_sb.st_size;
  if (x->length && pos + x->length < end) end = pos + x->length;
  size_t nsplits = 1, split = 0;
  if (x->split_size > 0 && end - pos > 0)
      nsplits = (end - pos) / x->split_size +
          ((end - pos) % x->split_size ? 1 : 0);
  while (pos == 0 || pos < end) {
      sum_task_t *stt = xmalloc(sizeof(sum_task_t));
      stt->src_name = xstrdup(filename);
      stt->dst_blksize = io_blksize(src_sb);
      stt->read_time = 0;
      stt->hash_time = 0;
      stt->sum_time = 0;
      stt->nsplits = nsplits;
      stt->split = split++;
      stt->start_offset = pos;
      stt->partial = x->offset || end < src_sb.st_size ? true : false;
      stt->hash_stack = xmalloc(x->hash_size);
      stt->hash_check = NULL;
      *x->hash_stat_tasks += 1;
      pos += x->split_size;
      if (nsplits > 1) {
          // stop after split size bytes
          stt->stop_offset = MIN(pos, end);
          if (stt->start_offset == x->offset) {
              sum_task_t *sttcp = xmalloc(sizeof(sum_task_t));
              sttcp->nsplits = nsplits;
              sttcp->split = nsplits;
              sttcp->start_offset = x->offset;
              sttcp->stop_offset = end;
              sttcp->partial = stt->partial;
              sttcp->src_name = xstrdup(filename);
              sttcp->hash_stack = xmalloc(nsplits * x->hash_size);
              sttcp->hash_check = h_check;
              if (x->store_hash) {
                  //TODO: check that won't overflow file
                  //      descriptors by keeping one open
                  // need to keep open descriptor for xattr operations
                /*TODO: this is different in msum since nothing is opened writable
                  sttcp->dest_desc =
                      open(dst_name, O_WRONLY | O_BINARY | x->write_mode);
                  if (sttcp->dest_desc < 0)
                      error(0, errno, _("warning: unable to open %s for storing hash"), quote(dst_name));
                */
                  //TODO: additional error handling?
              }
              // send stt copy to hash handler
              omp_q_push(x->send_q, sttcp);
          }
      } else {
          // stop at end of file
          stt->stop_offset = end;
          stt->hash_check = h_check;
      }
      omp_q_push(x->task_q, stt);
      if (nsplits == 1) break;
  }
  return true;
do_stdin:
#endif
// < PZK

  if (is_stdin)
    {
      have_read_stdin = true;
      fp = stdin;
      if (O_BINARY && *binary)
        {
          if (*binary < 0)
            *binary = ! isatty (STDIN_FILENO);
          if (*binary)
            xfreopen (NULL, "rb", stdin);
        }
    }
  else
    {
      fp = fopen (filename, (O_BINARY && *binary ? "rb" : "r"));
      if (fp == NULL)
        {
          error (0, errno, "%s", filename);
          return false;
        }
    }

  err = DIGEST_STREAM (fp, bin_result);
  if (err)
    {
      error (0, errno, "%s", filename);
      if (fp != stdin)
        fclose (fp);
      return false;
    }

  if (!is_stdin && fclose (fp) != 0)
    {
      error (0, errno, "%s", filename);
      return false;
    }

  return true;
}

static bool
// PZK >
digest_check (struct sum_options *x, const char *checkfile_name)
// < PZK
{
  FILE *checkfile_stream;
  uintmax_t n_properly_formatted_lines = 0;
  uintmax_t n_mismatched_checksums = 0;
  uintmax_t n_open_or_read_failures = 0;
  unsigned char bin_buffer_unaligned[DIGEST_BIN_BYTES + DIGEST_ALIGN];
  /* Make sure bin_buffer is properly aligned. */
  unsigned char *bin_buffer = ptr_align (bin_buffer_unaligned, DIGEST_ALIGN);
  uintmax_t line_number;
  char *line;
  size_t line_chars_allocated;
  bool is_stdin = STREQ (checkfile_name, "-");

  if (is_stdin)
    {
      have_read_stdin = true;
      checkfile_name = _("standard input");
      checkfile_stream = stdin;
    }
  else
    {
      checkfile_stream = fopen (checkfile_name, "r");
      if (checkfile_stream == NULL)
        {
          error (0, errno, "%s", checkfile_name);
          return false;
        }
    }

  line_number = 0;
  line = NULL;
  line_chars_allocated = 0;
  do
    {
      char *filename IF_LINT (= NULL);
      int binary;
      unsigned char *hex_digest IF_LINT (= NULL);
      ssize_t line_length;

      ++line_number;
      if (line_number == 0)
        error (EXIT_FAILURE, 0, _("%s: too many checksum lines"),
               checkfile_name);

      line_length = getline (&line, &line_chars_allocated, checkfile_stream);
      if (line_length <= 0)
        break;

      /* Remove any trailing newline.  */
      if (line[line_length - 1] == '\n')
        line[--line_length] = '\0';

// PZK >
      off_t stop;
      if (sscanf(line, "#mutil#%lld-%lld", &x->offset, &stop) != 2) {
        x->offset = 0;
        x->length = 0;
      } else {
        x->length = stop - x->offset;
      }
      size_t iline = 0;
      if (!strncmp(line, "#mutil#", 7)) {
        iline = strcspn(&line[7], "#") + 8;
        if (iline > line_length) continue;
        line_length -= iline;
      } else 
      /* Ignore comment lines, which begin with a '#' character.  */
      if (line[0] == '#')
        continue;

      if (! (split_3(&line[iline], line_length, &hex_digest, &binary, &filename)
// < PZK
             && ! (is_stdin && STREQ (filename, "-"))
             && hex_digits (hex_digest)))
        {
          if (warn)
            {
              error (0, 0,
                     _("%s: %" PRIuMAX
                       ": improperly formatted %s checksum line"),
                     checkfile_name, line_number,
                     DIGEST_TYPE_STRING);
            }
        }
      else
        {
          static const char bin2hex[] = { '0', '1', '2', '3',
                                          '4', '5', '6', '7',
                                          '8', '9', 'a', 'b',
                                          'c', 'd', 'e', 'f' };
          bool ok;

          ++n_properly_formatted_lines;

// PZK >
          unsigned char *h_check = xstrdup(hex_digest);
          ok = digest_file (x, h_check, filename, &binary, bin_buffer);
          continue;
// < PZK

          if (!ok)
            {
              ++n_open_or_read_failures;
              if (!status_only)
                {
                  printf (_("%s: FAILED open or read\n"), filename);
                  fflush (stdout);
                }
            }
          else
            {
              size_t digest_bin_bytes = digest_hex_bytes / 2;
              size_t cnt;
              /* Compare generated binary number with text representation
                 in check file.  Ignore case of hex digits.  */
              for (cnt = 0; cnt < digest_bin_bytes; ++cnt)
                {
                  if (tolower (hex_digest[2 * cnt])
                      != bin2hex[bin_buffer[cnt] >> 4]
                      || (tolower (hex_digest[2 * cnt + 1])
                          != (bin2hex[bin_buffer[cnt] & 0xf])))
                    break;
                }
              if (cnt != digest_bin_bytes)
                ++n_mismatched_checksums;

              if (!status_only)
                {
                  if (cnt != digest_bin_bytes)
                    printf ("%s: %s\n", filename, _("FAILED"));
                  else if (!quiet)
                    printf ("%s: %s\n", filename, _("OK"));
                  fflush (stdout);
                }
            }
        }
    }
  while (!feof (checkfile_stream) && !ferror (checkfile_stream));

  free (line);

  if (ferror (checkfile_stream))
    {
      error (0, 0, _("%s: read error"), checkfile_name);
      return false;
    }

  if (!is_stdin && fclose (checkfile_stream) != 0)
    {
      error (0, errno, "%s", checkfile_name);
      return false;
    }

  if (n_properly_formatted_lines == 0)
    {
      /* Warn if no tests are found.  */
      error (0, 0, _("%s: no properly formatted %s checksum lines found"),
             checkfile_name, DIGEST_TYPE_STRING);
    }
  else
    {
      if (!status_only)
        {
          if (n_open_or_read_failures != 0)
            error (0, 0,
                   ngettext ("WARNING: %" PRIuMAX " of %" PRIuMAX
                             " listed file could not be read",
                             "WARNING: %" PRIuMAX " of %" PRIuMAX
                             " listed files could not be read",
                             select_plural (n_properly_formatted_lines)),
                   n_open_or_read_failures, n_properly_formatted_lines);

          if (n_mismatched_checksums != 0)
            {
              uintmax_t n_computed_checksums =
                (n_properly_formatted_lines - n_open_or_read_failures);
              error (0, 0,
                     ngettext ("WARNING: %" PRIuMAX " of %" PRIuMAX
                               " computed checksum did NOT match",
                               "WARNING: %" PRIuMAX " of %" PRIuMAX
                               " computed checksums did NOT match",
                               select_plural (n_computed_checksums)),
                     n_mismatched_checksums, n_computed_checksums);
            }
        }
    }

  return (n_properly_formatted_lines != 0
          && n_mismatched_checksums == 0
          && n_open_or_read_failures == 0);
}

// PZK >
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

int
main (int argc, char **argv)
{
  unsigned char bin_buffer_unaligned[DIGEST_BIN_BYTES + DIGEST_ALIGN];
  /* Make sure bin_buffer is properly aligned. */
  unsigned char *bin_buffer = ptr_align (bin_buffer_unaligned, DIGEST_ALIGN);
  bool do_check = false;
  int opt;
  bool ok = true;
  int binary = -1;

  /* Setting values of global variables.  */
  initialize_main (&argc, &argv);
  set_program_name (argv[0]);
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  atexit (close_stdout);

// PZK >
  struct sum_options x;
  sum_option_init (&x);
// < PZK

  while ((opt = getopt_long (argc, argv, "bctw", long_options, NULL)) != -1)
    switch (opt)
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
            error(0, 0, _("Note: buffer size has been adjusted to %lld"), new_bs);
          x.buffer_size = new_bs * 1024 * 1024;
          break;
        case DIRECT_READ_OPTION:
          x.read_mode = O_DIRECT;
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
#ifdef POSIX_FADV_DONTNEED
        case FADVISE_READ_OPTION:
          x.fadvise_read = true;
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
              error(0, 0, _("Note: split size has been adjusted to %lld"), new_ss);
            x.split_size = new_ss * 1024 * 1024;
          }
          break;
        case THREADS_OPTION:
          x.threads = (int) strtol(optarg, (char **) NULL, 10);
          if (x.threads < 1 || x.threads > 512)
            error (EXIT_FAILURE, 0, _("invalid number of threads"));
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
            error(0, 0, _("Note: hash leaf size has been adjusted to %lld"), new_ls);
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
        case STORE_HASH_OPTION:
          x.store_hash = true;
          break;
#endif
#if HAVE_LIBMPI && defined(_OPENMP)
        case MPI_OPTION:
          x.mpi = true;
          break;
#endif
#if HAVE_LIBGNUTLS && defined(_OPENMP)
        case LISTEN_PORT_OPTION:
          x.listen_port = (int) strtol(optarg, (char **) NULL, 10);
          if (x.listen_port < 1 || x.listen_port > 65535)
            error (EXIT_FAILURE, 0, _("invalid listen port"));
          break;
        case MANAGER_HOST_OPTION:
          if (getaddrinfo(optarg, NULL, NULL, &x.mgr_ai))
            error (EXIT_FAILURE, 0, _("unable to resolve manager host"));
          break;
        case MANAGER_PORT_OPTION:
          x.mgr_port = (int) strtol(optarg, (char **) NULL, 10);
          if (x.mgr_port < 1 || x.mgr_port > 65535)
            error (EXIT_FAILURE, 0, _("invalid manager port"));
          break;
        case PASSWORD_FILE_OPTION:
          x.pw_file = xstrdup(optarg);
          break;
#endif
// < PZK
      case 'b':
        binary = 1;
        break;
      case 'c':
        do_check = true;
        break;
      case STATUS_OPTION:
        status_only = true;
        warn = false;
        quiet = false;
        break;
      case 't':
        binary = 0;
        break;
      case 'w':
        status_only = false;
        warn = true;
        quiet = false;
        break;
      case QUIET_OPTION:
        status_only = false;
        warn = false;
        quiet = true;
        break;
      case_GETOPT_HELP_CHAR;
      case_GETOPT_VERSION_CHAR (PROGRAM_NAME, AUTHORS);
      default:
        usage (EXIT_FAILURE);
      }

  min_digest_line_length = MIN_DIGEST_LINE_LENGTH;
  digest_hex_bytes = DIGEST_HEX_BYTES;

  if (0 <= binary && do_check)
    {
      error (0, 0, _("the --binary and --text options are meaningless when "
                     "verifying checksums"));
      usage (EXIT_FAILURE);
    }

  if (status_only & !do_check)
    {
      error (0, 0,
       _("the --status option is meaningful only when verifying checksums"));
      usage (EXIT_FAILURE);
    }

  if (warn & !do_check)
    {
      error (0, 0,
       _("the --warn option is meaningful only when verifying checksums"));
      usage (EXIT_FAILURE);
    }

  if (quiet & !do_check)
    {
      error (0, 0,
       _("the --quiet option is meaningful only when verifying checksums"));
      usage (EXIT_FAILURE);
    }

  if (!O_BINARY && binary < 0)
    binary = 0;

  if (optind == argc)
    argv[argc++] = bad_cast ("-");
// PZK >
  else if (x.read_stdin)
    error (EXIT_FAILURE, 0, _("--read_stdin cannot be used with other arguments"));
  if (x.read_stdin && do_check)
    error (EXIT_FAILURE, 0, _("--read_stdin cannot be used with -c/--check"));
  if (x.read_mode && x.fadvise_read) {
#if DEFAULT_DIRECT_READ
    x.read_mode = 0;
#else
    error(0, 0, _("Note: --fadvise disabled in favor of --direct-read"));
    x.fadvise_read = false;
#endif
  }
#if HAVE_LIBGCRYPT
  //TODO: temporarily disable options that excercise filesystem bugs
  if (x.store_hash) {
    error(0, 0, _("Note: hash stores have been temporarily disabled in this version"));
    x.store_hash = false;
  }
  //TODO: reenable above when filesystem bugs are fixed
  if ((x.offset || x.length) && x.store_hash)
    error(EXIT_FAILURE, 0, _("cannot store hash during partial file copy"));
  if (do_check && x.store_hash)
    error (EXIT_FAILURE, 0, _("cannot use --store-hash when verifying checksums"));
  if (x.split_size > 0 && x.split_size < x.buffer_size) {
    error(0, 0, _("Note: split size has been adjusted to the buffer size"));
    x.split_size = x.buffer_size;
  }
  if (x.split_size > 0 && x.split_size < x.hash_leaf_size) {
    error(0, 0, _("Note: hash leaf size has been adjusted to the split size"));
    x.hash_leaf_size = x.split_size;
  }
  if (!x.hash_leaf_size) {
    error(0, 0, _("Note: hash leaf size has been adjusted to 1GiB"));
    x.hash_leaf_size = 1024 * 1024 * 1024;
  }
  x.hash_size = gcry_md_get_algo_dlen(x.hash_type);
  min_digest_line_length = 2 * x.hash_size + 2 + 1;
  digest_hex_bytes = 2 * x.hash_size;
#endif
#if HAVE_LIBGNUTLS && defined(_OPENMP)
  if (x.mgr_ai != NULL && x.mgr_port)
    ((struct sockaddr_in *) x.mgr_ai->ai_addr)->sin_port = htons(x.mgr_port);
  if (x.mgr_ai != NULL && x.mgr_port == 0 || x.mgr_ai == NULL && x.mgr_port)
    error (EXIT_FAILURE, 0, _("must specify both manager host and manager port"));
  if (x.listen_port && x.mgr_port)
    error (EXIT_FAILURE, 0, _("cannot use --listen-port with --manager-port"));
  if (x.listen_port && x.pw_file) {
    struct stat st;
    // delay changing pw_file until after password generation
    char *tmppw = xmalloc(strlen(x.pw_file) + 4);
    x.mg_file = xmalloc(strlen(x.pw_file) + 4);
    sprintf(tmppw, "%s.pw", x.pw_file);
    sprintf(x.mg_file, "%s.mg", x.pw_file);
    if (stat(x.mg_file, &st) < 0 && stat(tmppw, &st) < 0) {
      if (srp_generate_auth(x.pw_file, tmppw, x.mg_file) < 0)
        error (EXIT_FAILURE, 0, _("unable to create manager password files"));
    } else if (stat(x.mg_file, &st) < 0) {
      error (EXIT_FAILURE, 0,
          _("manager modulus/generator file %s does not exist"),
          quote(x.mg_file));
    } else if (stat(tmppw, &st) < 0) {
      error (EXIT_FAILURE, 0, _("manager password file %s does not exist"),
          quote(tmppw));
    }
    free(x.pw_file);
    x.pw_file = tmppw;
  } else if (x.pw_file) {
    struct passwd *pw = getpwuid(getuid());
    if (pw == NULL)
        error (EXIT_FAILURE, 0, _("unable to determine user name"));
    x.user = xstrdup(pw->pw_name);
    FILE *f = fopen(x.pw_file, "r");
    if (f == NULL)
      error (EXIT_FAILURE, 0, _("unable to read user password file"));
    x.pass = xmalloc(32);
    if (fread(x.pass, 16, 1, f) < 1)
      error (EXIT_FAILURE, 0, _("unable to read user password"));
    x.pass[16] = 0;
  }
#endif

#ifdef _OPENMP
  int pid = 0, procs = 1;
  int hash_stat_done = 0;
  int main_done = 0;
# if HAVE_LIBMPI
  if (x.mpi) {
    MPI_Init(NULL, NULL);
    MPI_Comm_rank(MPI_COMM_WORLD, &pid);
    MPI_Comm_size(MPI_COMM_WORLD, &procs);
    // add a thread for MPI handler on main node
    if (pid == 0) x.threads++;
  }
# endif
  // add a thread for TCP handler on main node
  if (x.listen_port) x.threads++;
  // add a thread for file/TCP handler on main/other nodes
  x.threads++;
  // add a thread for stat/hash handler on main node
  if (!x.mgr_port && pid == 0) x.threads++;

  omp_set_num_threads(x.threads);
  bool oks[x.threads];
  omp_q_t task_q;
  omp_q_init(&task_q, x.threads, sizeof(sum_task_t));
  x.task_q = &task_q;
  omp_q_t send_q;
  omp_q_init(&send_q, x.threads, sizeof(void *));
  x.send_q = &send_q;

# if HAVE_LIBGCRYPT
  gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
  if (!gcry_check_version(GCRYPT_VERSION))
    error (EXIT_FAILURE, 0, _("libgcrypt version mismatch"));
  gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
  gcry_control(GCRYCTL_ENABLE_M_GUARD, 0);
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
# endif
# if HAVE_LIBGNUTLS
  if (x.listen_port || x.mgr_port) {
    gnutls_global_init();
    gnutls_global_init_extra();
  }
#endif

# pragma omp parallel
{
  int tid = omp_get_thread_num();
  oks[tid] = true;

  if (!x.mgr_port && pid == 0 && tid == 2) {
    ////////////////////////////////////
    // stat/hash handler on main node //
    ////////////////////////////////////
    struct timespec tts[2];
    if (x.print_stats) {
      fprintf(stderr, _("      size        rd_mbs  hs_mbs  sm_mbs  file\n"));
      fprintf(stderr, _("      ----        ------  ------  ------  ----\n"));
      clock_gettime(CLOCK_REALTIME, &tts[0]);
    }
    off_t tsize = 0;
    int maxstts = 128;
    sum_task_t **stts = xcalloc(maxstts, sizeof(sum_task_t *));
    int nstts = 0;
    long long done_tasks = 0;
    while (!main_done || *x.hash_stat_tasks > done_tasks) {
      //TODO: timeout on pop?
      sum_task_t *stt = omp_q_pop(&send_q);
      if (stt != NULL && stt->split != stt->nsplits) done_tasks++;
      if (stt == NULL || stt->src_name == NULL) {
        //TODO: do something with error?
        continue;
      }
      if (x.print_stats && stt->split != stt->nsplits) {
        tsize += stt->stop_offset - stt->start_offset;
        double mb = (stt->stop_offset - stt->start_offset) / 1000.0 / 1000.0;
        fprintf(stderr, _("%16lld  %6.1f  %6.1f  %6.1f  %s"),
            stt->stop_offset - stt->start_offset, mb / stt->read_time,
            mb / stt->hash_time, mb / stt->sum_time, stt->src_name);
        if (stt->nsplits > 1)
            fprintf(stderr, _(" (%lu/%lu)"), stt->split + 1, stt->nsplits);
        fprintf(stderr, _("\n"));
      }

      if (stt->nsplits == 1) {
        if (stt->hash_check != NULL) {
            print_check(&x, stt);
        } else {
            print_hash(&x, stt);
        }
      }

      if (stt->nsplits <= 1) {
        free(stt->src_name);
        free(stt->hash_stack);
        free(stt->hash_check);
        free(stt);
        continue;
      }

      int index;
      int empty = -1;
      // find existing entry and/or free slot
      for (index = 0; index < maxstts; index++) {
          if (stts[index] == NULL) {
              if (empty < 0) empty = index;
              continue;
          }
          if (!strcmp(stt->src_name, stts[index]->src_name)) break;
      }
      if (index >= maxstts) {
          // this is the first split received
          if (empty == -1) {
              // no free slot found so expand array
              maxstts *= 2;
              //TODO: should probably error out if array gets too big
              xrealloc(stts, maxstts * sizeof(sum_task_t *));
              bzero(&stts[maxstts / 2], maxstts / 2 * sizeof(sum_task_t *));
              empty = index;
          }
          // first stt has special field values including
          //   split = nsplits, stop_offset = file size,
          //   dest_desc = open fd, and hash_stack of size nsplits * hash size
          stts[empty] = stt;
      } else {
#if HAVE_LIBGCRYPT
        // copy final hash onto shared hash stack
        memcpy(&stts[index]->hash_stack[stt->split * x.hash_size],
            stt->hash_stack, x.hash_size);
        free(stt->hash_stack);
#endif
        free(stt->src_name);
        free(stt);
        stt = stts[index];
        // this works because split will be nsplits in first stt received
        if (--stt->split == 0) {
#if HAVE_LIBGCRYPT
            // finalize hash if last
            gcry_md_hd_t ctx;
            gcry_md_open(&ctx, x.hash_type, 0);
            hash_tree_t htt;
            htt.n_hash_total = 0;
            htt.hash_ctx = &ctx;
            htt.hash_ctx_len = 0;
//TODO:            if (x.store_hash) htt.xattr = xmalloc(ATTR_MAX_VALUELEN);
            htt.xattr_len = 0;
            // this works because dest_desc will be open in first stt received
            //TODO: htt.fd = stt->dest_desc;
            htt.stack_len = 0;
            // don't compute root of tree when printing/checking subtrees
            if (!x.check_tree)
                hash_final(&htt, stt, &x, 0, stt->nsplits,
                    stt->stop_offset - stt->start_offset);
            // print or check hash
            if (stt->hash_check != NULL) {
                print_check(&x, stt);
            } else {
                print_hash(&x, stt);
            }
            // clean up
            //TODO if (x.store_hash) close(stt->dest_desc);
            gcry_md_close(ctx);
            if (x.store_hash) free(htt.xattr);
            free(stt->hash_stack);
            free(stt->hash_check);
#endif
            free(stt->src_name);
            free(stt);
            stts[index] = NULL;
            //TODO: if last, then set done for tcp, etc.
        }
      }
    }
//TODO: there is something in the 4n.8t case causing this to hang at the end
     if (x.print_stats) {
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
    if (x.mpi) {
        // send message to MPI handler on main node to break out of
        // a final receive called just before hash_stat_done is set
        long long sz = -1;
        MPI_Send(&sz, 1, MPI_LONG_LONG, 0, 1, MPI_COMM_WORLD);
    }
# endif
# if HAVE_LIBGNUTLS
  } else if (x.mgr_port && tid == 0) {
    ////////////////////////////////
    // TCP handler on other nodes //
    ////////////////////////////////
    // initialize tls/srp
    gnutls_session_t tls_sess;
    gnutls_srp_client_credentials_t srp_cred;
    gnutls_srp_allocate_client_credentials(&srp_cred);
    gnutls_srp_set_client_credentials(srp_cred, x.user, x.pass);

    int nulls = 0;
    int null_task = 0;
    int nonnull_task = 0;

    while (nulls < x.threads - 1) {
      sum_task_t *stt = omp_q_pop(&send_q);
      if (stt == NULL && null_task) {
        nulls++;
        omp_q_push(&task_q, NULL);
        continue;
      } else if (stt != NULL) {
        nonnull_task = 1;
      }

      int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      if (sock < 0)
        error(EXIT_FAILURE, 0, _("unable to create socket"));

      size_t src_size = 0;
      ssize_t rc = connect(sock, x.mgr_ai->ai_addr, sizeof(struct sockaddr_in));
      if (!rc) {
        // initialize tls session
        gnutls_init(&tls_sess, GNUTLS_CLIENT);
        gnutls_priority_set_direct(tls_sess, "NORMAL:+SRP", NULL);
        gnutls_credentials_set(tls_sess, GNUTLS_CRD_SRP, srp_cred);
        gnutls_transport_set_ptr(tls_sess, (gnutls_transport_ptr_t) sock);
        if (gnutls_handshake(tls_sess) < 0) {
            error(0, 0, _("unable to authenticate to server"));
            //TODO: can this cause deadlocK?
            omp_q_push(&send_q, NULL);
            continue;
        }
      } else {
        if (nonnull_task) {
            nulls++;
            omp_q_push(&task_q, NULL);
            continue;
        }
        error(0, 0, _("connect failed...sleeping"));
        fflush(stderr);
        // wait until server starts
        sleep(1);
        //TODO: can this cause deadlocK?
        omp_q_push(&send_q, NULL);
        // probably want some check so don't loop forever
        continue;
      }


      if (stt != NULL) {
        // send final status with times and hash
        src_size = strlen(stt->src_name) + 1;
        rc |= gnutls_record_send(tls_sess, &src_size, sizeof(src_size));
        rc |= gnutls_record_send(tls_sess, stt->src_name, src_size);
        rc |= gnutls_record_send(tls_sess, stt->hash_stack, x.hash_size);
        rc |= gnutls_record_send(tls_sess, stt, sizeof(sum_task_t));
        if (stt->hash_check != NULL)
            rc |= gnutls_record_send(tls_sess, stt->hash_check,
                2 * x.hash_size);
        if (rc < 0)
            error(0, 0, _("unable to send final status to server"));
            //TODO: do something else like requeue stt?
        free(stt->src_name);
        free(stt->hash_check);
        free(stt->hash_stack);
        free(stt);
      } else {
        // send task request
        src_size = 0;
        rc |= gnutls_record_send(tls_sess, &src_size, sizeof(src_size));

        // receive task request
        rc |= gnutls_record_recv(tls_sess, &src_size, sizeof(src_size));
        if (rc < 0 || src_size == 0) {
          null_task = 1;
          nulls++;
          omp_q_push(&task_q, NULL);
        } else {
          if (rc > 0) {
              char *src_tmp = xmalloc(src_size);
              stt = xmalloc(sizeof(sum_task_t));
              stt->hash_check = NULL;
              rc |= gnutls_record_recv(tls_sess, src_tmp, src_size);
              rc |= gnutls_record_recv(tls_sess, stt, sizeof(sum_task_t));
              if (rc > 0 && stt->hash_check != NULL) {
                stt->hash_check = xmalloc(2 * x.hash_size + 1);
                rc |= gnutls_record_recv(tls_sess, stt->hash_check,
                    2 * x.hash_size);
                stt->hash_check[2 * x.hash_size] = 0;
              }
              //TODO: this section still needs work??
              if (rc > 0) {
                  stt->src_name = src_tmp;
                  stt->hash_stack = xmalloc(x.hash_size);
                  omp_q_push(&task_q, stt);
              } else {
                  free(src_tmp);
                  free(stt->hash_check);
                  free(stt);
              }
          }
        }
      }
      if (rc >= 0 || src_size > 0) {
        // shutdown tls session
        gnutls_bye(tls_sess, GNUTLS_SHUT_RDWR);
        shutdown(sock, SHUT_RDWR);
        gnutls_deinit(tls_sess);
      }
    }
    // free tls/srp resources
    gnutls_srp_free_client_credentials(srp_cred);
    gnutls_global_deinit();
  } else if (x.listen_port && tid == 1) {
    //////////////////////////////
    // TCP handler on main node //
    //////////////////////////////
    // initialize tls/srp
    gnutls_srp_server_credentials_t srp_cred;
    gnutls_srp_allocate_server_credentials(&srp_cred);
    gnutls_srp_set_server_credentials_file(srp_cred, x.pw_file, x.mg_file);

    int server_sock, client_sock;
    struct sockaddr_in server_sa, client_sa;
    socklen_t client_len = sizeof(client_sa);

    server_sa.sin_family = AF_INET;
    server_sa.sin_addr.s_addr = htonl(INADDR_ANY);
    server_sa.sin_port = htons(x.listen_port);

    server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock < 0)
        error(EXIT_FAILURE, 0, _("unable to create socket"));
    if (fcntl(server_sock, F_SETFL, O_NONBLOCK) < 0)
        error(EXIT_FAILURE, 0, _("unable to set socket option"));
    if (bind(server_sock, (struct sockaddr *) &server_sa, sizeof(server_sa)) < 0)
        error(EXIT_FAILURE, 0, _("unable to bind to socket"));
    if (listen(server_sock, SOMAXCONN) < 0)
        error(EXIT_FAILURE, 0, _("unable to listen on socket"));

    struct pollfd sfds[1];
    sfds[0].fd = server_sock;
    sfds[0].events = POLLIN;

    int null_task = 0;

    while (!main_done || !hash_stat_done) {
        if (poll(sfds, 1, 1000) <= 0) continue;

        gnutls_session_t tls_sess;
        gnutls_init(&tls_sess, GNUTLS_SERVER);
        gnutls_priority_set_direct(tls_sess, "NORMAL:+SRP", NULL);
        gnutls_credentials_set(tls_sess, GNUTLS_CRD_SRP, srp_cred);

        client_sock =
            accept(server_sock, (struct sockaddr *) &client_sa, &client_len);
        if (client_sock < 0) continue;
        gnutls_transport_set_ptr(tls_sess, (gnutls_transport_ptr_t) client_sock);
         if (gnutls_handshake(tls_sess) < 0) {
            error(0, 0, _("warning: failed authentication attempt from %s:%d"),
                inet_ntoa(client_sa.sin_addr), ntohs(client_sa.sin_port));
            continue;
        }

        size_t src_size;
        ssize_t rc = 0;
        sum_task_t *stt;
        //TODO: need timeouts throughout here
        if (gnutls_record_recv(tls_sess, &src_size, sizeof(src_size)) < 0) continue;
        if (src_size > 0) {
          char *src_tmp = xmalloc(src_size);
          unsigned char *hash_tmp = xmalloc(x.hash_size);
          stt = xmalloc(sizeof(sum_task_t));
          stt->hash_check = NULL;
          rc |= gnutls_record_recv(tls_sess, src_tmp, src_size);
          rc |= gnutls_record_recv(tls_sess, hash_tmp, x.hash_size);
          rc |= gnutls_record_recv(tls_sess, stt, sizeof(sum_task_t));
          if (rc > 0 && stt->hash_check != NULL) {
              stt->hash_check = xmalloc(2 * x.hash_size + 1);
              rc |= gnutls_record_recv(tls_sess, stt->hash_check,
                  2 * x.hash_size);
              stt->hash_check[2 * x.hash_size] = 0;
          }
          //TODO: this section still needs work??
          if (rc > 0) {
              stt->src_name = src_tmp;
              stt->hash_stack = hash_tmp;
              omp_q_push(&send_q, stt);
          } else {
              free(src_tmp);
              free(hash_tmp);
              free(stt->hash_check);
              stt->src_name = NULL;
              // indicate error with null src
              omp_q_push(&send_q, stt);
              //TODO: see if this technique can be used elsewhere
          }
        } else {
            stt = null_task ? NULL : omp_q_pop(&task_q);
            if (stt == NULL) {
                null_task = 1;
                src_size = 0;
                rc |= gnutls_record_send(tls_sess, &src_size, sizeof(src_size));
            } else {
                // this assumes same arch on client/server
                src_size = strlen(stt->src_name) + 1;
                rc |= gnutls_record_send(tls_sess, &src_size, sizeof(src_size));
                rc |= gnutls_record_send(tls_sess, stt->src_name, src_size);
                rc |= gnutls_record_send(tls_sess, stt, sizeof(sum_task_t));
                if (stt->hash_check != NULL)
                    rc |= gnutls_record_send(tls_sess, stt->hash_check,
                        2 * x.hash_size);
                if (rc <= 0) {
                    omp_q_push(&task_q, stt);
                    error(0, 0, _("warning: failure responding to client (will retry)"));
                } else {
                    free(stt->src_name);
                    free(stt->hash_check);
                    free(stt->hash_stack);
                    free(stt);
                }
            }
        }
        gnutls_bye(tls_sess, GNUTLS_SHUT_WR);
        close(client_sock);
        gnutls_deinit(tls_sess);
    }
    close(server_sock);
    gnutls_srp_free_server_credentials(srp_cred);
    gnutls_global_deinit();
# endif
# if HAVE_LIBMPI
  } else if (pid != 0 && tid == 0) {
    ////////////////////////////////
    // MPI handler on other nodes //
    ////////////////////////////////
    int nulls = 0;
    int null_task = 0;
    int nonnull_task = 0;

    while (nulls < x.threads - 1) {
      sum_task_t *stt = omp_q_pop(&send_q);
      if (stt == NULL && null_task) {
        nulls++;
        omp_q_push(&task_q, NULL);
        continue;
      } else if (stt != NULL) {
        nonnull_task = 1;
      }

      size_t src_size, chk_size;
      long long sz;
      int pos = 0;

      if (stt != NULL) {
        // send final status with times and hash
        src_size = strlen(stt->src_name) + 1;
        chk_size = stt->hash_check == NULL ?  0 : strlen(stt->hash_check) + 1;
        sz = src_size + chk_size + x.hash_size + sizeof(sum_task_t);
        MPI_Send(&sz, 1, MPI_LONG_LONG, 0, 1, MPI_COMM_WORLD);

        // pack stt into one big byte array
        char pack[sz];
        // this assumes same arch on client/server
        MPI_Pack(&src_size, sizeof(src_size),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&chk_size, sizeof(chk_size),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(stt->src_name, src_size,
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        if (chk_size)
            MPI_Pack(stt->hash_check, chk_size,
                MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(stt->hash_stack, x.hash_size,
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&stt->dst_blksize, sizeof(stt->dst_blksize),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&stt->read_time, sizeof(stt->read_time),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&stt->hash_time, sizeof(stt->hash_time),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&stt->sum_time, sizeof(stt->sum_time),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&stt->start_offset, sizeof(stt->start_offset),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&stt->stop_offset, sizeof(stt->stop_offset),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&stt->nsplits, sizeof(stt->nsplits),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
        MPI_Pack(&stt->split, sizeof(stt->split),
            MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);

        MPI_Send(pack, pos, MPI_PACKED, 0, 1, MPI_COMM_WORLD);

        free(stt->src_name);
        free(stt->hash_check);
        free(stt->hash_stack);
        free(stt);
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
            // unpack stt from one big byte array
            char pack[sz];
            if (MPI_Recv(pack, sz, MPI_PACKED, 0, 1, MPI_COMM_WORLD, &stat))
                continue;
            // this assumes same arch on client/server
            MPI_Unpack(pack, sz, &pos, &src_size, sizeof(src_size),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &chk_size, sizeof(chk_size),
                MPI_BYTE, MPI_COMM_WORLD);

            stt = xmalloc(sizeof(sum_task_t));
            stt->src_name = xmalloc(src_size);
            stt->hash_stack = xmalloc(x.hash_size);
            MPI_Unpack(pack, sz, &pos, stt->src_name, src_size,
                MPI_BYTE, MPI_COMM_WORLD);
            if (chk_size) {
                stt->hash_check = xmalloc(chk_size);
                MPI_Unpack(pack, sz, &pos, stt->hash_check, chk_size,
                    MPI_BYTE, MPI_COMM_WORLD);
            } else {
                stt->hash_check = NULL;
            }
            MPI_Unpack(pack, sz, &pos, &stt->dst_blksize, sizeof(stt->dst_blksize),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->read_time, sizeof(stt->read_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->hash_time, sizeof(stt->hash_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->sum_time, sizeof(stt->sum_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->start_offset, sizeof(stt->start_offset),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->stop_offset, sizeof(stt->stop_offset),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->nsplits, sizeof(stt->nsplits),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->split, sizeof(stt->split),
                MPI_BYTE, MPI_COMM_WORLD);

            omp_q_push(&task_q, stt);
        }
      }
    }
  } else if (x.mpi && pid == 0 && tid == 1) {
    //////////////////////////////
    // MPI handler on main node //
    //////////////////////////////
    int null_task = 0;
    MPI_Status stat;
    long long sz;
    int mpi_recv = 0;

    while (!main_done || !hash_stat_done || x.mpi && mpi_recv < 2) {
        if (MPI_Recv(&sz, 1, MPI_LONG_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG,
                MPI_COMM_WORLD, &stat)) break;

        size_t src_size, chk_size;
        sum_task_t *stt;
        int pos = 0;

        if (sz > 0) {
            // unpack stt from one big byte array
            char pack[sz];
            if (MPI_Recv(pack, sz, MPI_PACKED, stat.MPI_SOURCE,
                    stat.MPI_TAG, MPI_COMM_WORLD, &stat)) continue;
            // this assumes same arch on client/server
            MPI_Unpack(pack, sz, &pos, &src_size, sizeof(src_size),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &chk_size, sizeof(chk_size),
                MPI_BYTE, MPI_COMM_WORLD);

            stt = xmalloc(sizeof(sum_task_t));
            stt->src_name = xmalloc(src_size);
            stt->hash_stack = xmalloc(x.hash_size);
            MPI_Unpack(pack, sz, &pos, stt->src_name, src_size,
                MPI_BYTE, MPI_COMM_WORLD);
            if (chk_size) {
                stt->hash_check = xmalloc(chk_size);
                MPI_Unpack(pack, sz, &pos, stt->hash_check, chk_size,
                    MPI_BYTE, MPI_COMM_WORLD);
            } else {
                stt->hash_check = NULL;
            }
            MPI_Unpack(pack, sz, &pos, stt->hash_stack, x.hash_size,
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->dst_blksize, sizeof(stt->dst_blksize),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->read_time, sizeof(stt->read_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->hash_time, sizeof(stt->hash_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->sum_time, sizeof(stt->sum_time),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->start_offset, sizeof(stt->start_offset),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->stop_offset, sizeof(stt->stop_offset),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->nsplits, sizeof(stt->nsplits),
                MPI_BYTE, MPI_COMM_WORLD);
            MPI_Unpack(pack, sz, &pos, &stt->split, sizeof(stt->split),
                MPI_BYTE, MPI_COMM_WORLD);

            omp_q_push(&send_q, stt);
        } else if (sz == 0) {
            stt = null_task ? NULL : omp_q_pop(&task_q);
            if (stt == NULL) {
                null_task = 1;
                sz = 0;
                MPI_Send(&sz, 1, MPI_LONG_LONG, stat.MPI_SOURCE,
                    stat.MPI_TAG, MPI_COMM_WORLD);
            } else {
                src_size = strlen(stt->src_name) + 1;
                chk_size = stt->hash_check == NULL ?
                    0 : strlen(stt->hash_check) + 1;
                sz = src_size + chk_size + sizeof(sum_task_t);
                MPI_Send(&sz, 1, MPI_LONG_LONG, stat.MPI_SOURCE,
                    stat.MPI_TAG, MPI_COMM_WORLD);
                // pack stt into one big byte array
                char pack[sz];
                // this assumes same arch on client/server
                MPI_Pack(&src_size, sizeof(src_size),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&chk_size, sizeof(chk_size),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(stt->src_name, src_size,
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                if (chk_size)
                    MPI_Pack(stt->hash_check, chk_size,
                        MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&stt->dst_blksize, sizeof(stt->dst_blksize),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&stt->read_time, sizeof(stt->read_time),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&stt->hash_time, sizeof(stt->hash_time),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&stt->sum_time, sizeof(stt->sum_time),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&stt->start_offset, sizeof(stt->start_offset),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&stt->stop_offset, sizeof(stt->stop_offset),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&stt->nsplits, sizeof(stt->nsplits),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);
                MPI_Pack(&stt->split, sizeof(stt->split),
                    MPI_BYTE, pack, sz, &pos, MPI_COMM_WORLD);

                MPI_Send(pack, pos, MPI_PACKED, stat.MPI_SOURCE, stat.MPI_TAG,
                    MPI_COMM_WORLD);
                free(stt->src_name);
                free(stt->hash_check);
                free(stt->hash_stack);
                free(stt);
            }
        } else {
            // main and hash/stat done message to prevent deadlock
            mpi_recv++;
        }
    }
# endif
  } else if (tid != 0) {
    //////////////////////////////
    // sum handler on all nodes //
    //////////////////////////////
    // indicate ready for request on other nodes
    if (x.mgr_port || pid != 0) omp_q_push(&send_q, NULL);
    sum_task_t *stt;
    while ((stt = omp_q_pop(&task_q)) != NULL) {
      struct timespec ts[2];
      if (x.print_stats) clock_gettime(CLOCK_REALTIME, &ts[0]);
      oks[tid] &= sum_task(stt, &x);
      if (x.print_stats) {
        clock_gettime(CLOCK_REALTIME, &ts[1]);
        stt->sum_time = (double) (
          (double) ts[1].tv_sec + (double) ts[1].tv_nsec / (double) 1.0e9 -
          (double) ts[0].tv_sec - (double) ts[0].tv_nsec / (double) 1.0e9);
      }
      omp_q_push(&send_q, stt);
      // indicate ready for request on other nodes
      if (x.mgr_port || pid != 0) omp_q_push(&send_q, NULL);
    }
  } else {
#endif
// < PZK

  for (; optind < argc; ++optind)
    {
      char *file = argv[optind];
// PZK >
      if (x.read_stdin) {
        size_t buf_max = MIN(PATH_MAX, 32 * 1024);
        char *buf = xmalloc(buf_max);

        while (fgets(buf, buf_max, stdin) != NULL) {
            buf[strcspn(buf, "\n")] = '\0';
            if (file[0] == '\0') {
                //TODO: error handling if string too long
                continue;
            }
            size_t irange = strcspn(buf, " ");
            if (buf[irange] == '\0') irange = 0;
            else buf[irange++] = '\0';
            file = unescape(buf, 0);
            if (file == NULL) {
                //TODO: error handling if can't unescape
                continue;
            }
            int file_is_binary = binary;
            if (irange > 0) {
                off_t x1, x2;
                while (sscanf(&buf[irange], "%lld-%lld", &x1, &x2) == 2) {
                    x.offset = x1;
                    x.length = x2 - x1;
                    if (! digest_file (&x, NULL, file, &file_is_binary,
                            bin_buffer)) ok = false;
                    irange += strcspn(&buf[irange], ",");
                    if (buf[irange] == ',') irange++;
                }
            } else {
                x.offset = 0;
                x.length = 0;
                if (! digest_file (&x, NULL, file, &file_is_binary, bin_buffer))
                    ok = false;
            }
        }
        break;
      }
// < PZK
      if (do_check)
        ok &= digest_check (&x, file);
      else
        {
          int file_is_binary = binary;

          if (! digest_file (&x, NULL, file, &file_is_binary, bin_buffer))
            ok = false;
          else
            {
// PZK >
#ifdef _OPENMP
              if (!STREQ (file, "-")) continue;
#endif
// < PZK
              size_t i;

              /* Output a leading backslash if the file name contains
                 a newline or backslash.  */
              if (strchr (file, '\n') || strchr (file, '\\'))
                putchar ('\\');

              for (i = 0; i < (digest_hex_bytes / 2); ++i)
                printf ("%02x", bin_buffer[i]);

              putchar (' ');
              if (file_is_binary)
                putchar ('*');
              else
                putchar (' ');

              /* Translate each NEWLINE byte to the string, "\\n",
                 and each backslash to "\\\\".  */
              for (i = 0; i < strlen (file); ++i)
                {
                  switch (file[i])
                    {
                    case '\n':
                      fputs ("\\n", stdout);
                      break;

                    case '\\':
                      fputs ("\\\\", stdout);
                      break;

                    default:
                      putchar (file[i]);
                      break;
                    }
                }
              putchar ('\n');
            }
        }
    }
// PZK >
#ifdef _OPENMP
    // indicate that main thread is done traversing file system
    main_done = 1;
    // send terminating NULL task to stat/hash thread
    omp_q_push(&send_q, NULL);
    // send terminating NULL task to all worker threads
    for (int i = 0; i < x.threads - 1; i++)
        omp_q_push(&task_q, NULL);
# if HAVE_LIBMPI
    if (x.mpi) {
        // send message to MPI handler on main node to break out of
        // a final receive called just before main_done is set
        long long sz = -1;
        MPI_Send(&sz, 1, MPI_LONG_LONG, 0, 1, MPI_COMM_WORLD);
    }
# endif
  }
}

# if HAVE_LIBMPI
  if (x.mpi) MPI_Finalize();
# endif

  // destroy all queues
  omp_q_destroy(&send_q);
  omp_q_destroy(&task_q);

  //TODO: this no longer works with mpi/tcp
  // reduce oks array to single value
  for (int i = 0; i < x.threads; i++)
    ok &= oks[i];
#endif
// < PZK

  if (have_read_stdin && fclose (stdin) == EOF)
    error (EXIT_FAILURE, errno, _("standard input"));

  exit (ok ? EXIT_SUCCESS : EXIT_FAILURE);
}


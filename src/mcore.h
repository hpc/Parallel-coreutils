// PZK >
/* mcore.h -- core functions for copying/hashing files

   Copyright 2010 United States Government National Aeronautics and
   Space Administration (NASA).  No copyright is claimed in the United
   States under Title 17, U.S. Code.  All Other Rights Reserved.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License Version 3 with
   Additional Terms below (per Section 7 of GPL V3).

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* Written by Paul Kolano.  */

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

#ifndef MCORE_H
# define MCORE_H
#define _OPENMP 1
#define HAVE_LIBMPI 1
# include <config.h>
# include "copy.h"
# include "mcore-omp.h"

///////////////////
//// Hash Tree ////
///////////////////

# if HAVE_LIBGCRYPT
#  include <gcrypt.h>

typedef struct {
    off_t n_hash_total;
    gcry_md_hd_t *hash_ctx;
    size_t hash_ctx_len;
    char *xattr;
    size_t xattr_len;
    char *stack;
    size_t stack_len;
    int fd;
} hash_tree_t;

void hash_final(hash_tree_t *htt, copy_reg_t *crt, struct cp_options *co,
        size_t start, size_t end, off_t size);
void hash_leaf(hash_tree_t *htt, copy_reg_t *crt, struct cp_options *co,
    const char *buf, ssize_t buf_len);
void hash_tree(hash_tree_t *htt, copy_reg_t *crt, struct cp_options *co,
    const char *buf, off_t n_read_total, off_t size);

# endif


////////////////////////////////
//// Secure Remote Password ////
////////////////////////////////

# if HAVE_LIBGNUTLS

int srp_generate_auth(char *client_pw_file, char *pw_file, char *mg_file);

# endif

#endif
// < PZK


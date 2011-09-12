// PZK >
/* mcore.c -- core functions for copying/hashing files

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
#undef HAVE_LIBGNUTLS
#include "mcore.h"

///////////////////
//// Hash Tree ////
///////////////////

#if HAVE_LIBGCRYPT
# include <gcrypt.h>
# include "copy.h"

void hash_tree(hash_tree_t *htt, copy_reg_t *crt, struct cp_options *co,
        const char *buf, off_t n_read_total, off_t size)
{
    off_t n_hash = 0;
    while (htt->n_hash_total + co->hash_leaf_size <= n_read_total) {
        hash_leaf(htt, crt, co, &buf[n_hash],
            co->hash_leaf_size - htt->hash_ctx_len);
        n_hash += co->hash_leaf_size - htt->hash_ctx_len;
        htt->hash_ctx_len = 0;
        htt->n_hash_total += co->hash_leaf_size;
    }
    if (n_read_total >= crt->stop_offset - crt->start_offset) {
        // last iteration
        if (n_read_total > htt->n_hash_total)
            hash_leaf(htt, crt, co, &buf[n_hash],
                n_read_total - htt->n_hash_total - htt->hash_ctx_len);
        if (co->store_hash && crt->split == 0) {
            // first split will write summary info
            char val[128];
            sprintf(val, "%s", (char *) gcry_md_algo_name(co->hash_type));
            //TODO:fsetxattr(htt->fd, "user.hash.type", val, strlen(val), 0);
            //TODO: check for errors
            sprintf(val, "%lld", co->hash_leaf_size);
            //TODO:fsetxattr(htt->fd, "user.hash.leaf.size", val, strlen(val), 0);
        }
        if (co->store_hash && htt->xattr_len > 0) {
            // store leftover xattr buffer
            char name[128];
            sprintf(name, "user.hash.tree.%lld.%lld",
                crt->start_offset, crt->stop_offset);
            //TODO:fsetxattr(htt->fd, name, htt->xattr, htt->xattr_len, 0);
            //TODO: check for errors
        }
    } else {
        // store in hash context for next iteration
        if (n_read_total - htt->n_hash_total > 0)
            gcry_md_write(*htt->hash_ctx, &buf[n_hash],
                n_read_total - htt->n_hash_total - htt->hash_ctx_len);
        htt->hash_ctx_len = n_read_total - htt->n_hash_total;
    }
}

void hash_final(hash_tree_t *htt, copy_reg_t *crt, struct cp_options *co,
        size_t start, size_t end, off_t size)
{
    if (start + 1 >= end) return;

    // find nearest power of 2 less than (end - start)
    size_t n = 1;
    size_t leafs = end - start;
    while (n < leafs) n <<= 1;
    n >>= 1;

    // compute hash of left and right subtrees
    gcry_md_hd_t ctx;
    gcry_md_open(&ctx, co->hash_type, 0);
    hash_final(htt, crt, co, start, start + n, size);
    gcry_md_write(ctx, &crt->hash_stack[start * co->hash_size], co->hash_size);
    if (end > start + n) {
        hash_final(htt, crt, co, start + n, end, size);
        gcry_md_write(ctx, &crt->hash_stack[(start + n) * co->hash_size],
            co->hash_size);
    }
    unsigned char *hash = gcry_md_read(ctx, 0);
    memcpy(&crt->hash_stack[start * co->hash_size], hash, co->hash_size);
    gcry_md_close(ctx);

    if (co->store_hash) {
        // store start off_t
        *((off_t *) &htt->xattr[htt->xattr_len]) = start * co->split_size;
        htt->xattr_len += sizeof(off_t);

        // store end off_t
        off_t end_off = end * co->split_size;
        if (end == crt->nsplits) end_off = size;
        *((off_t *) &htt->xattr[htt->xattr_len]) = end_off;
        htt->xattr_len += sizeof(off_t);

        // store hash in xattr buffer
        memcpy(&htt->xattr[htt->xattr_len],
            &crt->hash_stack[start * co->hash_size], co->hash_size);
        htt->xattr_len += co->hash_size;

        if (htt->xattr_len + co->hash_size + 2 * sizeof(off_t) >
                1/*TODO:ATTR_MAX_VALUELEN*/) {
            // xattr is full so store contents and reset xattr buffer
            char name[128];
            sprintf(name, "user.hash.tree.%lld.%lld", start * co->split_size, end_off);
            //TODO:fsetxattr(htt->fd, name, htt->xattr, htt->xattr_len, 0);
            //TODO: check for errors

            htt->xattr_len = 0;
        }
    }
}

void hash_leaf(hash_tree_t *htt, copy_reg_t *crt, struct cp_options *co,
        const char *buf, ssize_t buf_len)
{
    if (htt->hash_ctx_len + buf_len > 0 || htt->n_hash_total == 0) {
        // something to hash or zero-length file

        // compute hash of block [start, end)
        if (buf_len > 0) gcry_md_write(*htt->hash_ctx, buf, buf_len);
        unsigned char *hash = gcry_md_read(*htt->hash_ctx, 0);

        // store hash on stack
        memcpy(&htt->stack[htt->stack_len], hash, co->hash_size);
        htt->stack_len += co->hash_size;

        if (co->store_hash) {
            // store start off_t
            *((off_t *) &htt->xattr[htt->xattr_len]) =
                crt->start_offset + htt->n_hash_total;
            htt->xattr_len += sizeof(off_t);

            // store end off_t
            *((off_t *) &htt->xattr[htt->xattr_len]) =
                crt->start_offset + htt->n_hash_total + htt->hash_ctx_len + buf_len;
            htt->xattr_len += sizeof(off_t);

            // store hash in xattr buffer
            memcpy(&htt->xattr[htt->xattr_len], hash, co->hash_size);
            htt->xattr_len += co->hash_size;

            if (htt->xattr_len + co->hash_size + 2 * sizeof(off_t) >
                    1/*TODO:ATTR_MAX_VALUELEN*/) {
                // xattr is full so store contents and reset xattr buffer
                char name[128];
                sprintf(name, "user.hash.tree.%lld.%lld",
                    crt->start_offset + htt->n_hash_total,
                    crt->start_offset + htt->n_hash_total +
                        htt->hash_ctx_len + buf_len);
                //TODO:fsetxattr(htt->fd, name, htt->xattr, htt->xattr_len, 0);
                //TODO: check for errors

                htt->xattr_len = 0;
            }
        }
    }

    off_t total = htt->n_hash_total + htt->hash_ctx_len + buf_len;
    off_t total_pow2 = total;

    // for final partial leaf node, compute hash subtree as if it were full
    if (htt->hash_ctx_len + buf_len < co->hash_leaf_size) {
        off_t n = 1;
        double leafs = total / (double) co->hash_leaf_size;
        while (n < leafs) n <<= 1;
        total_pow2 = n * co->hash_leaf_size;
    }

    // compute hash subtree from bottom up
    ssize_t i = 1;
    while (htt->stack_len >= 2 * co->hash_size && total_pow2 != 0 &&
            total_pow2 / (i * co->hash_leaf_size) % 2 == 0) {
        if (total_pow2 - i * co->hash_leaf_size < total) {
            // compute hash of last two hashes on stack
            gcry_md_reset(*htt->hash_ctx);
            gcry_md_write(*htt->hash_ctx,&htt->stack[htt->stack_len - 2 * co->hash_size],
                co->hash_size);
            gcry_md_write(*htt->hash_ctx, &htt->stack[htt->stack_len - co->hash_size],
                co->hash_size);
            htt->stack_len -= 2 * co->hash_size;
            unsigned char *hash = gcry_md_read(*htt->hash_ctx, 0);

            // store hash on stack
            memcpy(&htt->stack[htt->stack_len], hash, co->hash_size);
            htt->stack_len += co->hash_size;

            if (co->store_hash) {
                // store start off_t
                *((off_t *) &htt->xattr[htt->xattr_len]) =
                    crt->start_offset + total_pow2 - 2 * i * co->hash_leaf_size;
                htt->xattr_len += sizeof(off_t);

                // store end off_t
                *((off_t *) &htt->xattr[htt->xattr_len]) =
                    crt->start_offset + total;
                htt->xattr_len += sizeof(off_t);

                // store hash in xattr buffer
                memcpy(&htt->xattr[htt->xattr_len], hash, co->hash_size);
                htt->xattr_len += co->hash_size;

                if (htt->xattr_len + co->hash_size + 2 * sizeof(off_t) >
                        1/*TODO:ATTR_MAX_VALUELEN*/) {
                    // xattr is full so store contents and reset xattr buffer
                    char name[128];
                    sprintf(name, "user.hash.tree.%lld.%lld",
                        crt->start_offset + total_pow2 - 2 * i * co->hash_leaf_size,
                        crt->start_offset + total);
                    //TODO:fsetxattr(htt->fd, name, htt->xattr, htt->xattr_len, 0);
                    //TODO: check for errors

                    htt->xattr_len = 0;
                }
            }
        }
        i *= 2;
    }
    gcry_md_reset(*htt->hash_ctx);
}

#endif


////////////////////////////////
//// OpenMP Semaphore Queue ////
////////////////////////////////

#ifdef _OPENMP

void omp_sem_init(omp_sem_t *s, int size, int free) {
    s->free = free;
    s->size = size;
    omp_init_lock(&s->mutex);
    // an array of locks is used for waiting instead of a single lock
    // as gcc does not seem to properly release multiple threads waiting
    // on the same lock if multiple unlocks are executed before any
    // waiting thread is actually released
    s->waits = (omp_lock_t *) calloc(size, sizeof(omp_lock_t));
    for (int i = 0; i < size; i++) {
        omp_init_lock(&s->waits[i]);
        omp_set_lock(&s->waits[i]);
    }
}

void omp_sem_destroy(omp_sem_t *s) {
    for (int i = 0; i < s->size; i++) {
        omp_destroy_lock(&s->waits[i]);
    }
    free(s->waits);
    omp_destroy_lock(&s->mutex);
}

void omp_sem_procure(omp_sem_t *s) {
    omp_set_lock(&s->mutex);
    s->free--;
    if (s->free < 0) {
        int lock = s->size + s->free;
        omp_unset_lock(&s->mutex);
        omp_set_lock(&s->waits[lock]);
    } else {
        omp_unset_lock(&s->mutex);
    }
}

void omp_sem_vacate(omp_sem_t *s) {
    omp_set_lock(&s->mutex);
    if (s->free < 0) {
        omp_unset_lock(&s->waits[s->size + s->free]);
    }
    s->free++;
    omp_unset_lock(&s->mutex);
}

int omp_sem_free(omp_sem_t *s) {
    return s->free;
}

void omp_q_init(omp_q_t *q, int size, size_t ptr_size) {
    omp_sem_init(&q->max_sem, size, size);
    omp_sem_init(&q->min_sem, size, 0);
    omp_init_lock(&q->q_lock);
    q->i_read = 0;
    q->i_write = 0;
    q->size = size;
    q->ptr_size = ptr_size;
    q->vals = (void **) calloc(size, ptr_size);
}

void omp_q_destroy(omp_q_t *q) {
    free(q->vals);
    omp_destroy_lock(&q->q_lock);
    omp_sem_destroy(&q->min_sem);
    omp_sem_destroy(&q->max_sem);
}

void omp_q_push(omp_q_t *q, void *val) {
    omp_sem_procure(&q->max_sem);
    omp_set_lock(&q->q_lock);
    q->vals[q->i_write] = val;
    q->i_write = (q->i_write + 1) % q->size;
    omp_unset_lock(&q->q_lock);
    omp_sem_vacate(&q->min_sem);
}

void *omp_q_pop(omp_q_t *q) {
    omp_sem_procure(&q->min_sem);
    omp_set_lock(&q->q_lock);
    void *val = q->vals[q->i_read];
    q->i_read = (q->i_read + 1) % q->size;
    omp_unset_lock(&q->q_lock);
    omp_sem_vacate(&q->max_sem);
    return val;
}

int omp_q_size(omp_q_t *q) {
    return (q->size + q->i_write - q->i_read) % q->size;
}

#endif


////////////////////////////////
//// Secure Remote Password ////
////////////////////////////////

// < PZK

// PZK >
/* mcore-omp.h -- OpenMP semaphores and semaphore-protected queues

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

#ifndef MCORE_OMP_H
# define MCORE_OMP_H

# include <stdlib.h>

# ifdef _OPENMP
#  include <omp.h>

typedef struct {
    omp_lock_t mutex;
    omp_lock_t *waits;
    int free;
    int size;
} omp_sem_t;

void omp_sem_init(omp_sem_t *s, int size, int free);
void omp_sem_destroy(omp_sem_t *s);
void omp_sem_procure(omp_sem_t *s);
void omp_sem_vacate(omp_sem_t *s);
int omp_sem_free(omp_sem_t *s);

# endif

typedef struct {
# ifdef _OPENMP
    omp_sem_t max_sem;
    omp_sem_t min_sem;
    omp_lock_t q_lock;
# endif
    int size;
    size_t ptr_size;
    int i_read;
    int i_write;
    void **vals;
} omp_q_t;

# ifdef _OPENMP

void omp_q_init(omp_q_t *q, int size, size_t ptr_size);
void omp_q_destroy(omp_q_t *q);
void omp_q_push(omp_q_t *q, void *val);
void *omp_q_pop(omp_q_t *q);
int omp_q_size(omp_q_t *q);

# endif
#endif
// < PZK


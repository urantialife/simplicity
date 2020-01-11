#include "jets.h"

#include "callonce.h"
#include "sha256.h"
#include "secp256k1/secp256k1_impl.h"

static inline void read8s(unsigned char* x, size_t n, frameItem* frame) {
  for(; n; --n) *(x++) = (unsigned char)read8(frame);
}

static inline void write8s(frameItem* frame, const unsigned char* x, size_t n) {
  for(; n; --n) write8(frame, *(x++));
}

/* Read a secp256k1 field element value from the 'src' frame, advancing the cursor 256 cells.
 *
 * Precondition: '*src' is a valid read frame for 256 more cells;
 *               NULL != r;
 */
static inline void read_fe(secp256k1_fe* r, frameItem* src) {
  unsigned char buf[32];

  read8s(buf, 32, src);
  if (!secp256k1_fe_set_b32(r, buf)) secp256k1_fe_normalize(r);
}

/* Write a secp256k1 field element value to the 'dst' frame, advancing the cursor 256 cells.
 * The field value 'r' is normalized as a side-effect.
 *
 * Precondition: '*dst' is a valid write frame for 256 more cells;
 *               NULL != r;
 */
static inline void write_fe(frameItem* dst, secp256k1_fe* r) {
  unsigned char buf[32];

  secp256k1_fe_normalize(r);
  secp256k1_fe_get_b32(buf, r);
  write8s(dst, buf, 32);
}

/* Skip 256 cells, the size of a secp256k1 field element value, in the 'dst' frame.
 *
 * Precondition: '*dst' is a valid write frame for 256 more cells;
 */
static inline void skip_fe(frameItem* dst) {
  skipBits(dst, 256);
}

/* Read a (non-infinity) secp256k1 affine group element value from the 'src' frame, advancing the cursor 512 cells.
 *
 * Precondition: '*src' is a valid read frame for 512 more cells;
 *               NULL != r;
 */
static inline void read_ge(secp256k1_ge* r, frameItem* src) {
  read_fe(&r->x, src);
  read_fe(&r->y, src);
  r->infinity = 0;
}

/* Read a secp256k1 jacobian group element value from the 'src' frame, advancing the cursor 768 cells.
 *
 * Precondition: '*src' is a valid read frame for 768 more cells;
 *               NULL != r;
 */
static inline void read_gej(secp256k1_gej* r, frameItem* src) {
  read_fe(&r->x, src);
  read_fe(&r->y, src);
  read_fe(&r->z, src);
  r->infinity = secp256k1_fe_is_zero(&r->z);
}

/* Write a secp256k1 jacobian group element value to the 'dst' frame, advancing the cursor 786 cells.
 * If 'r->infinity' then an fe_zero value to all coordinates in the 'dst' frame.
 * The components of 'r' may be normalized as a side-effect.
 *
 * Precondition: '*dst' is a valid write frame for 768 more cells;
 *               NULL != r;
 */
static inline void write_gej(frameItem* dst, secp256k1_gej* r) {
  if (r->infinity) {
    write32s(dst, (uint32_t[24]){0}, 24);
  } else {
    write_fe(dst, &r->x);
    write_fe(dst, &r->y);
    write_fe(dst, &r->z);
  }
}

/* Read a secp256k1 scalar element value from the 'src' frame, advancing the cursor 256 cells.
 *
 * Precondition: '*src' is a valid read frame for 256 more cells;
 *               NULL != r;
 */
static inline void read_scalar(secp256k1_scalar* r, frameItem* src) {
  unsigned char buf[32];

  read8s(buf, 32, src);
  secp256k1_scalar_set_b32(r, buf, NULL);
}

/* Write a secp256k1 scalar element value to the 'dst' frame, advancing the cursor 256 cells.
 *
 * Precondition: '*dst' is a valid write frame for 256 more cells;
 *               NULL != r;
 */
static inline void write_scalar(frameItem* dst, const secp256k1_scalar* r) {
  unsigned char buf[32];

  secp256k1_scalar_get_b32(buf, r);
  write8s(dst, buf, 32);
}

bool fe_sqrt(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused;

  secp256k1_fe r, a;
  read_fe(&a, &src);
  int result = secp256k1_fe_sqrt_var(&r, &a);
  if (writeBit(dst, result)) {
    write_fe(dst, &r);
  } else {
    skip_fe(dst);
  }
  return true;
}

bool offsetPoint(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused;

  secp256k1_gej r, a;
  secp256k1_ge b;
  secp256k1_fe rzr;
  read_gej(&a, &src);
  read_ge(&b, &src);
  secp256k1_gej_add_ge_var(&r, &a, &b, &rzr);
  write_fe(dst, &rzr);
  write_gej(dst, &r);
  return true;
}

static once_flag ecmult_static_initialized = ONCE_FLAG_INIT;
static struct {
   secp256k1_ecmult_context ctx;
   char alloc[SECP256K1_ECMULT_CONTEXT_PREALLOCATED_SIZE];
} ecmult_static;

static void ecmult_static_initialize(void) {
  void *prealloc = ecmult_static.alloc;
  secp256k1_ecmult_context_init(&ecmult_static.ctx);
  secp256k1_ecmult_context_build(&ecmult_static.ctx, &prealloc);
  assert(SECP256K1_ECMULT_CONTEXT_PREALLOCATED_SIZE == (char *)prealloc - ecmult_static.alloc);
}

static secp256k1_ecmult_context* ecmult_static_ctx(void) {
  call_once(&ecmult_static_initialized, &ecmult_static_initialize);
  return &ecmult_static.ctx;
}

bool ecmult(frameItem* dst, frameItem src, const txEnv* env) {
  (void) env; // env is unused;

  secp256k1_gej r, a;
  secp256k1_scalar na, ng;

  read_gej(&a, &src);
  read_scalar(&na, &src);
  read_scalar(&ng, &src);
  secp256k1_ecmult(ecmult_static_ctx(), &r, &a, &na, &ng);

  /* This jet's implementation of ecmult is defined to always outputs the jacobian coordinate (1, 1, 0)
   * if the result is the point at infinity.
   */
  if (r.infinity) {
    secp256k1_fe_set_int(&r.x, 1);
    secp256k1_fe_set_int(&r.y, 1);
  }
  write_gej(dst, &r);
  return true;
}

bool schnorrAssert(frameItem* dst, frameItem src, const txEnv* env) {
  (void) dst; // dst is unused;
  (void) env; // env is unused;

  unsigned char buf[64];
  secp256k1_xonly_pubkey pubkey;
  unsigned char msg[32];
  unsigned char sig[64];

  read8s(buf, 32, &src);
  if (!secp256k1_xonly_pubkey_parse(&pubkey, buf)) return false;

  read8s(msg, 32, &src);
  read8s(sig, 64, &src);

  return secp256k1_schnorrsig_verify(ecmult_static_ctx(), sig, msg, &pubkey);
}

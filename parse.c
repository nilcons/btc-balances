#define _GNU_SOURCE
#include <assert.h>
#include <search.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void hex_log(char* msg, unsigned char* buf, int size) {
  fprintf(stderr, msg);
  for (int i = 0; i < size; i++) {
    fprintf(stderr, "%02x", *(buf + i));
  }
  fprintf(stderr, "\n");
}

void hex_print(unsigned char* buf, int size) {
  for (int i = 0; i < size; i++) printf("%02x", *(buf + i));
}

// We store these (address, amount, utxos) triplets in a binary tree
// in memory, so we can group by address during processing, and then
// dump it all to stdout.  The binary tree is only compared by
// address, and then amount is summed, and utxos is increased by all
// utxo that is found for the same address.
#define MAX_INTERESTING_SCRIPT_LEN 25
typedef struct {
  unsigned char script[MAX_INTERESTING_SCRIPT_LEN]; // len sized
  unsigned char len; // current 22 or 25
  uint64_t amount;
  uint64_t utxos;
} address_data;

// TSEARCH COMPAT FOR ADDRESS_DATA
typedef address_data*const* nodep;

address_data* address_data_new(unsigned char* script, unsigned char len) {
  // zeroing of amount+utxos via calloc
  // zeroing of unused part of script via calloc
  address_data* ret = calloc(1, sizeof(address_data));
  ret->len = len;
  memcpy(ret->script, script, len);
  return ret;
}

int __address_data_compare(const address_data* a, const address_data* b) {
  return memcmp(a->script, b->script, MAX_INTERESTING_SCRIPT_LEN);
}
#define address_data_tinsert(tr, ni) (* (nodep) tsearch(ni, &tr, (__compar_fn_t) __address_data_compare))

static inline __attribute__((always_inline))
void __address_data_action(nodep nodep, VISIT visit, void* _ignored) {
  address_data* data = *nodep;
  if (visit == postorder || visit == leaf) {
    hex_print(data->script, MAX_INTERESTING_SCRIPT_LEN);
    printf(",%ld,%ld\n", data->utxos, data->amount);
  }
}
void address_data_action(const void* nodep, VISIT visit, void* closure) {
  __address_data_action(nodep, visit, closure);
}
// END OF TSEARCH COMPAT FOR ADDRESS_DATA

size_t read_input(void* buf, size_t size) {
  return fread(buf, 1, size, stdin);
}

uint64_t read_compactsize() {
  uint64_t ret = 0;
  assert(1 == read_input(&ret, 1));
  switch(ret) {
  case 253:
    assert(2 == read_input(&ret, 2));
    break;
  case 254:
    assert(4 == read_input(&ret, 4));
    break;
  case 255:
    assert(8 == read_input(&ret, 8));
    break;
  default:
  }
  return ret;
}

uint64_t read_varint() {
  uint64_t ret = 0;
  for (int i = 0; i < 9; ++i) {
    unsigned char next;
    assert(1 == read_input(&next, 1));
    ret <<= 7;
    ret += (next & 0x7f);
    if (next & 0x80) {
      ret += 1;
    } else {
      return ret;
    }
  }
  fprintf(stderr, "Too big read_varint\n");
  exit(255);
}

uint64_t decompress_amount(uint64_t x) {
  if (x == 0) return 0;

  x -= 1;
  uint64_t e = x % 10;
  x /= 10;
  uint64_t n = 0;
  if (e < 9) {
    uint64_t d = (x % 9) + 1;
    x /= 9;
    n = x * 10 + d;
  } else {
    n = x + 1;
  }
  while (e > 0) {
    n *= 10;
    e -= 1;
  }
  return n;
}

// returns 0 if this script is not interesting for us,
// otherwise returns the length of the script in bytes
unsigned char scriptpubkeybuf[10240];
int read_scriptpubkey() {
  uint64_t size = read_varint();
  switch(size) {
  case 0:
    // P2PKH
    // These are the old-school 1... addresses
    assert(20 == read_input(scriptpubkeybuf + 3, 20));

    // our special snowflake old school 1... address
    if (scriptpubkeybuf[22] == 0xf8) {
      scriptpubkeybuf[0] = 0x76;
      scriptpubkeybuf[1] = 0xa9;
      scriptpubkeybuf[2] = 0x14;
      scriptpubkeybuf[23] = 0x88;
      scriptpubkeybuf[24] = 0xac;
      return 25;
    }
    break;
  case 1:
    // P2SH
    // Not interesting for us
    assert(20 == read_input(scriptpubkeybuf, 20));
    break;
  case 2:
  case 3:
    // P2PK (compressed)
    // Not interesting for us
    assert(32 == read_input(scriptpubkeybuf, 32));
    break;
  case 4:
  case 5:
    // P2PK (uncompressed)
    // Not interesting for us
    assert(32 == read_input(scriptpubkeybuf, 32));
    break;
  default:
    // others (bare multisig, segwit etc.)
    // Interesting if 0014...
    assert(size - 6 <= 10000);
    assert(size - 6 == read_input(scriptpubkeybuf, size - 6));
    if (size - 6 == 22 && scriptpubkeybuf[0] == 0 && scriptpubkeybuf[1] == 0x14) {
      scriptpubkeybuf[22] = 0;
      scriptpubkeybuf[23] = 0;
      scriptpubkeybuf[24] = 0;
      return 22;
    }
  }

  return 0;
}

int main() {
  unsigned char buf[1024];
  assert(11 == read_input(buf, 11)); // magic (utxo\xff) + version (2) + network magic (\xf9\xbe\xb4\xd9)
  assert(0 == memcmp(buf, "utxo\xff\x02\x00\xf9\xbe\xb4\xd9", 11));

  unsigned char block_hash[32];
  assert(32 == read_input(block_hash, 32));

  uint64_t num_utxos;
  assert(8 == read_input(&num_utxos, 8));

  fprintf(stderr, "num_utxos: %lu\n", num_utxos);

  void* tree = NULL;
  uint64_t max_height = 0;
  int i = 0;
  for (; i < num_utxos;) {
    assert(32 == read_input(buf, 32)); // prevout_hash
    /* hex_dump("prevout_hash: ", buf, 32); */
    uint64_t coins_per_hash = read_compactsize();
    /* fprintf(stderr, "coins_per_hash: %lu\n", coins_per_hash); */

    for (int j = 0; j < coins_per_hash; ++j, ++i) {
      if (i % 1000000 == 0) {
        /* fprintf(stderr, "In-memory preprocessing: %3.2f%%\n", (100.0 * i) / num_utxos); */
        fprintf(stderr, "Dumping UTXOs to text: %3.2f%%\n", (100.0 * i) / num_utxos);
      }
      //      uint64_t prevout_index =
      read_compactsize();
      /* fprintf(stderr, "prevout_index: %lu\n", prevout_index); */

      uint64_t code = read_varint();
      /* fprintf(stderr, "code: %lu\n", code); */
      if ((code >> 1) > max_height)
        max_height = (code >> 1);
      /* fprintf(stderr, "height: %lu\n", (code >> 1)); */
      /* fprintf(stderr, "is_coinbase: %ld\n", (code &1)); */

      uint64_t amount = decompress_amount(read_varint());
      /* fprintf(stderr, "amount: %lu\n", amount); */

      int interesting = read_scriptpubkey();
      if (interesting) {
        hex_print(scriptpubkeybuf, interesting);
        printf(" %ld\n", amount);
        // Overcomplicated solution 1:
        /* address_data* new = address_data_new(scriptpubkeybuf, interesting); */
        /* address_data* inserted = address_data_tinsert(tree, new); */
        /* if (inserted != new) free(new); */
        /* // increase stuff */
        /* inserted->amount += amount; */
        /* inserted->utxos += 1; */
      }
    }
  }
  fprintf(stderr, "processed: %lu, max_height: %lu\n", num_utxos, max_height);

  // Check that we really finished in the input file.
  assert(0 == read_input(buf, 4096));

  twalk_r(tree, address_data_action, NULL);

  return 0;
}

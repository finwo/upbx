#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common/resp.h"
#include "domain/pbx/registration.h"
#include "finwo/assert.h"

void test_pattern_is_pattern(void) {
  ASSERT("empty is not pattern", registration_is_pattern(NULL) == 0);
  ASSERT("empty is not pattern", registration_is_pattern("") == 0);
  ASSERT("digits only not pattern", registration_is_pattern("200") == 0);
  ASSERT("x is pattern", registration_is_pattern("2xx") == 1);
  ASSERT("z is pattern", registration_is_pattern("2z") == 1);
  ASSERT("n is pattern", registration_is_pattern("2n") == 1);
  ASSERT(". is pattern", registration_is_pattern("2.") == 1);
  ASSERT("! is pattern", registration_is_pattern("2!") == 1);
  ASSERT("mixed pattern", registration_is_pattern("2nxx") == 1);
}

void test_pattern_exact_digits(void) {
  ASSERT("exact match 200", registration_match_pattern("200", "200") == 1);
  ASSERT("exact mismatch 200 vs 201", registration_match_pattern("200", "201") == 0);
  ASSERT("exact mismatch 200 vs 2000", registration_match_pattern("200", "2000") == 0);
  ASSERT("exact mismatch 200 vs 20", registration_match_pattern("200", "20") == 0);
}

void test_pattern_x(void) {
  ASSERT("x matches 0", registration_match_pattern("2xx", "200") == 1);
  ASSERT("x matches 5", registration_match_pattern("2xx", "205") == 1);
  ASSERT("x matches 9", registration_match_pattern("2xx", "209") == 1);
  ASSERT("x fails for letter", registration_match_pattern("2xx", "20a") == 0);
  ASSERT("x fails for short", registration_match_pattern("2xx", "20") == 0);
  ASSERT("x at end matches multiple", registration_match_pattern("200x", "2000") == 1);
}

void test_pattern_z(void) {
  ASSERT("z matches 1", registration_match_pattern("2z", "21") == 1);
  ASSERT("z matches 9", registration_match_pattern("2z", "29") == 1);
  ASSERT("z fails 0", registration_match_pattern("2z", "20") == 0);
}

void test_pattern_n(void) {
  ASSERT("n matches 2", registration_match_pattern("2n", "22") == 1);
  ASSERT("n matches 9", registration_match_pattern("2n", "29") == 1);
  ASSERT("n fails 0", registration_match_pattern("2n", "20") == 0);
  ASSERT("n fails 1", registration_match_pattern("2n", "21") == 0);
}

void test_pattern_dot(void) {
  ASSERT("dot matches one or more", registration_match_pattern("2.", "20") == 1);
  ASSERT("dot matches more", registration_match_pattern("2.", "201") == 1);
  ASSERT("dot fails for exact", registration_match_pattern("2.", "2") == 0);
}

void test_pattern_exclamation(void) {
  ASSERT("exclamation matches zero or more", registration_match_pattern("2!", "2") == 1);
  ASSERT("exclamation matches one", registration_match_pattern("2!", "20") == 1);
  ASSERT("exclamation matches more", registration_match_pattern("2!", "201") == 1);
}

void test_pattern_specificity(void) {
  ASSERT("literal more specific than x", registration_match_pattern("200", "200") == 1);
  ASSERT("x matches 0", registration_match_pattern("2xx", "200") == 1);
  ASSERT("dot matches one or more", registration_match_pattern("2.", "20") == 1);
}

int main(void) {
  RUN(test_pattern_is_pattern);
  RUN(test_pattern_exact_digits);
  RUN(test_pattern_x);
  RUN(test_pattern_z);
  RUN(test_pattern_n);
  RUN(test_pattern_dot);
  RUN(test_pattern_exclamation);
  RUN(test_pattern_specificity);
  return TEST_REPORT();
}

#include <cstdlib>

int main() {
  int *p = nullptr;
  *p = 42; // trigger SIGSEGV
  return 0;
}

#include <atomic>
#include <cxxabi.h>
#include <dlfcn.h>
#include <exception>
#include <libunwind.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <vector>

extern "C" void _Unwind_Resume(struct _Unwind_Exception *) __attribute__((weak));

static struct sigaction original_actions[NSIG];
static std::terminate_handler original_terminate_handler = nullptr;

namespace {
void safe_write(const char *msg) {
  write(STDERR_FILENO, msg, strlen(msg));
}

void safe_print_num(int num) {
  char buffer[16];
  int i = 0;
  bool negative = false;

  if (num < 0) {
    negative = true;
    num = -num;
  }

  do {
    buffer[i++] = '0' + (num % 10);
    num /= 10;
  } while (num > 0 && i < sizeof(buffer) - 1);

  if (negative && i < sizeof(buffer) - 1) {
    buffer[i++] = '-';
  }

  for (int j = 0; j < i / 2; ++j) {
    char tmp = buffer[j];
    buffer[j] = buffer[i - j - 1];
    buffer[i - j - 1] = tmp;
  }

  write(STDERR_FILENO, buffer, i);
}

void safe_print_hex(uintptr_t value) {
  const char *hexdigits = "0123456789abcdef";
  char buffer[16] = {0};

  for (int i = 15; i >= 0; --i) {
    buffer[i] = hexdigits[value & 0xf];
    value >>= 4;
  }

  safe_write("0x");
  write(STDERR_FILENO, buffer, 16);
}

class DemangleBuffer {
  static const size_t BUFFER_SIZE = 1024;
  char buffer[BUFFER_SIZE];

 public:
  const char *demangle(const char *name) {
    if (!name)
      return "<null>";

    if (!&_Unwind_Resume) {
      return name;
    }

    int status = 0;
    size_t length = BUFFER_SIZE;
    char *demangled = abi::__cxa_demangle(name, buffer, &length, &status);

    return demangled ? demangled : name;
  }
};

struct StackFrame {
  uintptr_t pc;
  uintptr_t offset;
  char sym[256];
};

std::vector<StackFrame> collect_stacktrace() {
  std::vector<StackFrame> frames;
  unw_cursor_t cursor;
  unw_context_t context;

  unw_getcontext(&context);
  unw_init_local(&cursor, &context);

  while (unw_step(&cursor) > 0) {
    StackFrame frame;
    unw_get_reg(&cursor, UNW_REG_IP, &frame.pc);
    if (frame.pc == 0)
      break;

    unw_get_proc_name(&cursor, frame.sym, sizeof(frame.sym), &frame.offset);
    frames.push_back(frame);
  }

  return frames;
}

void print_demangled_stacktrace() {
  static DemangleBuffer demangler;
  auto frames = collect_stacktrace();

  safe_write("\nCall stack:\n");
  for (const auto &frame : frames) {
    safe_print_hex(frame.pc);
    safe_write(": ");
    safe_write(demangler.demangle(frame.sym));
    safe_write(" + 0x");
    safe_print_hex(frame.offset);
    safe_write("\n");
  }
}
} // namespace

static std::atomic<bool> already_printed{false};

void signal_handler(int sig) {
  static std::atomic_flag lock = ATOMIC_FLAG_INIT;
  if (lock.test_and_set())
    return;

  if (!already_printed.exchange(true)) {
    safe_write("\nCaught signal: ");
    safe_print_num(sig);
    print_demangled_stacktrace();
  }

  if (original_actions[sig].sa_handler == SIG_DFL) {
    sigaction(sig, &original_actions[sig], nullptr);
    raise(sig);
  } else if (original_actions[sig].sa_handler != SIG_IGN) {
    original_actions[sig].sa_handler(sig);
  }

  _exit(128 + sig);
}

void terminate_handler() {
  if (!already_printed.exchange(true)) {
    safe_write("\nTerminate called\n");
    print_demangled_stacktrace();
  }

  std::set_terminate(original_terminate_handler);
  if (original_terminate_handler) {
    original_terminate_handler();
  }
  abort();
}

__attribute__((constructor)) void init() {
  const int signals[] = {SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS, SIGTERM};
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sigfillset(&sa.sa_mask);

  for (auto sig : signals) {
    sigaction(sig, &sa, &original_actions[sig]);
  }

  original_terminate_handler = std::set_terminate(terminate_handler);
  safe_write("Stack trace handler installed\n");
}

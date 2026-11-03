// Leaks are not the bug class this fleet fuzzes for; this hook turns LeakSanitizer off at build time.
extern "C" int __lsan_is_turned_off() { return 1; }

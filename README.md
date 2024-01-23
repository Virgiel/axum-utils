# Axum utils

Small utils library for axum based Rust web application

**Disclaimer: This project is intended for my personal use and I will not
improve or maintain it if I do not have the use of it. But you are free to use
and copy my code.**

## Static Opti

I often want to serve static files and I needed a solution that is secure and
efficient. Static opti take your statics files, compress them at their maximum,
precalculate their ETag and dump them in a single file. You can then mmap this
file and serve optimized static files with minimal computation and syscalls.

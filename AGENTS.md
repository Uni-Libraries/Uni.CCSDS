
# Agents Specification

* General
    * Write code in C23
    * Write tests in C++23 using Catch2 framework

* Documentation
    * before implementation read the following
        * [CCSDS-732.1-B-3](docs/standards/CCSDS-732.1-B-3%20Unified%20Space%20Data%20Link%20Protocol.pdf)
        * [docs/uslp.md](docs/uslp.md) 
        * [docs/uslp_pics.md](docs/uslp_pics.md) 
    * during implementation to point to the specific standard articles and USLP compliance items in the comments
    * adter implementation update PICS report [docs/uslp_pics.md](docs/uslp_pics.md) 

* Build and testing

```
cmake -S . -B build && cmake --build build -j && ctest --test-dir build --output-on-failure
```

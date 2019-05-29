# Open CAS Framework

Open CAS Framework (OCF) is high performance block storage caching meta-library
written in C. It's entirely platform and system independent, accessing system API
through user provided environment wrappers layer. OCF tightly integrates with the
rest of software stack, providing flawless, high performance, low latency caching
utility.

# In this readme:

* [Documentation](#documentation)
* [Source Code](#source)
* [Deployment](#deployment)
* [Examples](#examples)
* [Unit Tests](#unit_tests)
* [Build Test](#build_test)
* [Contributing](#contributing)
* [Security](#security)

## Documentation

Doxygen API documentation is available [here](http://open-cas.github.io/doxygen/ocf).  
More documentation, tutorial and examples will be available soon.

## Source Code

Source code is available in the official OCF GitHub repository:

~~~{.sh}
git clone https://github.com/open-cas/ocf
cd ocf
~~~

## Deployment

OCF doesn't compile as separate library. It's designed to be included into another
software stack. For this purpose OCF provides Makefile with two useful targets for
deploying its source into target directories. Assuming OCFDIR is OCF directory, and
SRCDIR and INCDIR are respectively your source and include directories, use following
commands to deploy OCF into your project:

~~~{.sh}
make -C $OCFDIF src O=$SRCDIR
make -C $OCFDIF inc O=$INCDIR
~~~

By default this will not copy OCF source files but create symbolic links to them,
to avoid source duplication and allow for easy OCF code modification. If you prefer
to copy OCF source files (e.g. you don't want to distribute whole OCF repository
as your submodule) you can use following commands:

~~~{.sh}
make -C $OCFDIF src O=$SRCDIR CMD=cp
make -C $OCFDIF inc O=$INCDIR CMD=cp
~~~

## Examples

OCF is shipped with examples, which are complete, compillable and working
programs, containing lot of comments that explain basics of caching. They
are great starting point for everyone who wants to start working with OCF.

Examples can be found in directory `example/`.

Each example contains Makefile which can be used to compile it.

## Unit Tests

OCF is shipped with dedicated unit test framework based on Cmocka.  
To run unit test you need to install following packages:
- Cmake (>= 3.8.1)
- Cmocka (>= 1.1.1)
- ctags (>= 5.8)

To run unit tests use following command:

~~~{.sh}
./tests/unit/framework/run_unit_tests.py
~~~

## Build Test

OCF repository contains basic build test. It uses default POSIX environment.
To run this test, use following commands:

~~~{.sh}
cd tests/build/
make
~~~

## Contributing

Feel like making OCF better? Don't hesitate to submit a pull request!  
You can find more information about our contribution process
[here](https://open-cas.github.io/contributing.html).  
In case of any questions feel free to contact [maintainer](mailto:robert.baldyga@intel.com).

## Security

To report a potential security vulnerability please follow the instructions
[here](https://open-cas.github.io/contributing.html#reporting-a-potential-security-vulnerability)

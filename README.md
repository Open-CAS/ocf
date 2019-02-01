# Open CAS Framework

Open CAS Framwework (OCF) is high performance block storage caching meta-library
written in C. It's entirely platform and system independent, accessing system API
through user provided environment wrappers layer. OCF tightly integrates with the
rest of software stack, providing flawless, high performance, low latency caching
utility.

# In this readme:

* [Documentation](#documentation)
* [Source Code](#source)
* [Deployment](#deployment)
* [Unit Tests](#tests)
* [Demo Build](#build)
* [Contributing](#contributing)

<a id="documentation"></a>
## Documentation

Doxygen API documentation is available [here](http://open-cas.github.io/doxygen/ocf).  
More documentation, tutorial and examples will be available soon.

<a id="source"></a>
## Source Code

Source code is available in the official OCF GitHub repository:

~~~{.sh}
git clone https://github.com/open-cas/ocf
cd ocf
~~~

<a id="deployment"></a>
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

<a id="tests"></a>
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

<a id="build"></a>
## Demo Build

OCF is shipped with some simple demo to compile and use OCF.  
You can try to build this demo to verify that you change can pass the compile.

~~~{.sh}
cd ./example/simple/
make
~~~

<a id="contributing"></a>
## Contributing

Feel like making OCF better? Don't hesitate to submit a pull request!  
In case of any questions feel free to contact [maintainer](mailto:robert.baldyga@intel.com).

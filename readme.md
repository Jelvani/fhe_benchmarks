

## Dependecies

* g++ >= 6.0
* cmake >= 3.5.1
* [Microsoft SEAL](https://github.com/microsoft/SEAL)
* [OpenFHE](https://github.com/openfheorg/openfhe-development)

## Build Instructions
After installing all dependecies, you can compile both benchmark programs by running in the root directory:

```sh
mkdir build && cd build
cmake ..
make -j2
```

This will produce 2 binaries in that directory that correspond to benchmarks compiled with each library.

## OpenFHE CMake Build Options

| OPTION_NAME    |    Value    |
| -----------    | ----------- |
| WITH_OPENMP    | OFF         |
| WITH_NATIVEOPT | ON          |

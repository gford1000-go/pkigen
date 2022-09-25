[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://en.wikipedia.org/wiki/MIT_License)
[![Documentation](https://img.shields.io/badge/Documentation-GoDoc-green.svg)](https://godoc.org/github.com/gford1000-go/pkigen)


PKIGEN | Geoff Ford
=================

PKIGEN provides unique public/private RSA key pairs, of the bit size required by the caller.

Optionally a public key can be provided by the caller, and the generated RSA key pair will 
then be returned, encrypted using that public key.

Installing and building the library
===================================

This project requires Go 1.18

To use this package in your own code, install it using `go get`:

    go get github.com/gford1000-go/pkigen

Then, you can include it in your project:

	import "github.com/gford1000-go/pkigen"

Alternatively, you can clone it yourself:

    git clone https://github.com/gford1000-go/pkigen.git

Testing and benchmarking
========================

To run all tests, `cd` into the directory and use:

	go test -v


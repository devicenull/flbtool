This is some tooling for interacting with Intel's FLB3 files (these are used for NIC firmware updates).

Usage:

* Retrieve the existing firmware from the nic with `bootutil64e -SI -NIC 1 -FILE nic.FLB`
* Extract FLB file with `./flbtool.py extract_firmware --input nic.FLB --output_directory fromintel`
* Make any necessary changes to the files in the output directory (ensure you keep the same json/filename formats!)
* Regenerate the FLB file with `./flbtool.py write_firmware --input_directory fromintel --output modified.FLB`
* Reprogram the FLB file into the nic with `bootutil64e -UP -FILE=modified.FLB`
There is no public documentation on this file format, so it's all been reverse engineered from existing FLB files.

Some of the chunks within the file are named 'Signature Image'.  It's unknown what exactly they are... there may be crypto signatures on some of the images.


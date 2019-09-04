#!/usr/bin/python

import argparse
import glob
import json
import logging
import os
import struct

from logging import debug, info, warning


logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s\t%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)


class JsonSerializable(object):

    def serialize(self):
        return json.dumps(self.__dict__)

    def __repr__(self):
        return self.serialize()

    @staticmethod
    def dumper(obj):
        if "serialize" in dir(obj):
            return obj.serialize()

        data = obj.__dict__
        data['__classname__'] = obj.__class__.__name__
        return data


class FLBHeader:
    HEADERFORMAT = (
        '<'
        '4s'    # Should be 'FLB3'
        'I'     # Total length of FLB3 header
        'B'     # Unknown
        'I'     # Total length of data blob
        'H'     # delimiter?  \x80\x86
        '80s'   # Segment description
        '3B'    # version #
    )
    # Total size of HEADERFORMAT
    HEADERSIZE = 98

    # Parse a full FLB header.  Returns the number of bytes consumed
    def parse(self, firmware):
        (self.magic, self.header_length, self.unknown1, self.data_length, self.delimiter,
            self.description, self.version1, self.version2, self.version3) = struct.unpack(FLBHeader.HEADERFORMAT, firmware[0:FLBHeader.HEADERSIZE])

        self.description = self.description.replace("\x00", '')
        self.logInfo()
        return FLBHeader.HEADERSIZE

    def deserialize(self, data):
        self.__dict__ = data
        self.logInfo()

    def logInfo(self):
        info('Version: %i.%i.%i Description: %s' % (self.version1, self.version2, self.version3, self.description))
        info('Header Length: %i Data Length: %i' % (self.header_length, self.data_length))

    def writeToFLB(self, output_file):
        output_file.write(struct.pack(FLBHeader.HEADERFORMAT, self.magic.encode('ascii'), self.header_length, self.unknown1, self.data_length, self.delimiter,
            self.description.encode('ascii'), self.version1, self.version2, self.version3))

class PCIDetails:
    HEADERFORMAT = (
        '<'
        'I'    # Seems like enum representing type of fw?
        # If you read an image from a NIC, these bytes are always 0, however
        # if you use the images Intel provides, these occasionally have some values
        # set.  It's weird this is an odd length.
        '37s'  # unknown
    )

    HEADERSIZE = 41

    # These are complete guesses based on existing files...
    # Is this maybe a bitmask?
    FLB_TYPES = {
        0x300: 'FLB_PXE',
        0x800: 'FLB_UEFI_DRIVER',
        0x1000: 'FLB_ISCSI_OPTION',
        0x2000: 'FLB_FCOE_OPTION',
        0x10000: 'FLB_COMBO_RULES',
        # seems to start with $CIV?
        0x100000: 'FLB_CIVD_BIN',
        0x100001: 'FLB_COMBO_IMAGE_VERSION_NAME',
        0x200000: 'FLB_OCD_OPTION',
        0x800000: 'FLB_CLP_LOADER',
        0x1000000: 'FLB_ISCSI_SETUP',
        # unsure wtf this is, name is '40G Interface Module'
        0x2000000: 'FLB_40G_INTERFACE',
        0x10000000: 'FLB_UEFI_X64_FCOE_DRIVER',
        0x20000000: 'FLB_SIGNATURE',
        # How does this differ from FLB_SIGNATURE?
        0x20000100: 'FLB_SIGNATURE_2',
    }

    def parse(self, firmware):
        (self.flb_type, self.unknown) = struct.unpack(PCIDetails.HEADERFORMAT, firmware[0:PCIDetails.HEADERSIZE])
        self.logInfo();

        return PCIDetails.HEADERSIZE

    def deserialize(self, data):
        self.__dict__ = data
        self.logInfo()

    def logInfo(self):
        if self.flb_type in PCIDetails.FLB_TYPES:
            info('FLB type: 0x%x (%s)' % (self.flb_type, PCIDetails.FLB_TYPES[self.flb_type]))
        else:
            info('FLB type: 0x%x (UNKNOWN)' % self.flb_type)

    def writeToFLB(self, output_file):
        output_file.write(struct.pack(PCIDetails.HEADERFORMAT, self.flb_type, self.unknown.encode('ascii')))


class PCIDeviceList:
    # seems plausible, BootImg.FLB came from a E-2186G box:
    # 01:00.0 Ethernet controller [0200]: Intel Corporation Ethernet Controller 10G X550T [8086:1563] (rev 01)
    #        Subsystem: Super Micro Computer Inc Device [15d9:0903]
    # https://pci-ids.ucw.cz/read/PC/8086/1563
    # gets parsed as:
    # DEBUG|8086:1563
    DEVICEFORMAT = (
        '<'
        'H'  # vendor, usually 8086
        'H'  # pci device ID,
        'H'  # subsystem vendor
        'H'  # subsystem id
        'H'  # unknown.  almost always 0
        'H'  # unknown.  almost always 0, the only other value I've seen is 0x4100
    )
    DEVICESIZE = 12

    def parse(self, firmware):
        devicepos = 0
        self.devices = []
        info('Supported PCI Devices:')
        while devicepos < len(firmware):
            device_args = struct.unpack(PCIDeviceList.DEVICEFORMAT, firmware[devicepos:devicepos + PCIDeviceList.DEVICESIZE])
            # Every supported pci device list is followed by an all-zeros entry
            # (and even segments with no supported devices have an all-zeros entry)
            newdevice = PCIDevice(*device_args)

            if newdevice.isValid():
                info(newdevice)

            self.devices.append(newdevice)

            devicepos += PCIDeviceList.DEVICESIZE

        return devicepos

    def deserialize(self, data):
        self.devices = data['devices']
        info('Supported PCI Devices:')
        for cur in self.devices:
            info(cur)

    def writeToFLB(self, output_file):
        for cur in self.devices:
            cur.writeToFLB(output_file)


class PCIDevice:
    def __init__(self, vendor, device, subvendor, subdevice, unk1, unk2):
        self.vendor = vendor
        self.device = device
        self.subvendor = subvendor
        self.subdevice = subdevice
        self.unk1 = unk1
        self.unk2 = unk2

    # Every device list entry ends with an all 0's PCIDevice
    def isValid(self):
        return self.vendor > 0 or self.device > 0 or self.subvendor > 0 or self.subdevice > 0 or self.unk1 > 0 or self.unk2 > 0

    def __str__(self):
        return '%04x:%04x subsys %04x:%04x unk %04x:%04x' % (self.vendor, self.device, self.subvendor, self.subdevice, self.unk1, self.unk2)

    def deserialize(self, data):
        self.__dict__ = data

    def writeToFLB(self, output_file):
        output_file.write(struct.pack(PCIDeviceList.DEVICEFORMAT, self.vendor, self.device, self.subvendor, self.subdevice, self.unk1, self.unk2))


class FirmwareData:
    def __init__(self, firmware):
        self.firmware = firmware

    def writeToFLB(self, output_file):
        output_file.write(self.firmware)


class FLBChunk:
    def __init__(self, chunknum):
        self.chunknum = chunknum
        info('FLB3 chunk %i' % chunknum)

    def parse(self, inputdata):
        pos = 0
        self.header = FLBHeader()
        pos += self.header.parse(inputdata[pos:pos + FLBHeader.HEADERSIZE])

        self.pcidetails = PCIDetails()
        pos += self.pcidetails.parse(inputdata[pos:pos + PCIDetails.HEADERSIZE])

        pci_devicelist_size = self.header.header_length - FLBHeader.HEADERSIZE - PCIDetails.HEADERSIZE

        self.pcidevices = PCIDeviceList()
        pos += self.pcidevices.parse(inputdata[pos:pos + pci_devicelist_size])

        # This is the actual firmware (or whatever else is in the blob)
        self.firmware = FirmwareData(inputdata[pos:pos + self.header.data_length])
        pos += self.header.data_length

        try:
            debug(hexdump.hexdump(self.firmware.firmware[0:8], 'return') + "\n")
        except NameError:
            pass

        return pos

    # This is necessary when we're regenerating an image from a list of chunks.  It's possible things like the firmware size
    # or various attributes within the header have changed
    def recalculateHeaders(self):
        self.header.data_length = len(self.firmware.firmware)
        self.header.header_length = FLBHeader.HEADERSIZE + PCIDetails.HEADERSIZE + (len(self.pcidevices.devices) * PCIDeviceList.DEVICESIZE)

    def extractToDisk(self, destination_dir):
        filename = os.path.join(destination_dir, 'chunk_%03i.bin' % self.chunknum)
        with open(filename, 'wb') as f:
            f.write(self.firmware.firmware)

        filename = os.path.join(destination_dir, 'chunk_%03i.json' % self.chunknum)
        metadata = {
            'header': self.header,
            'pcidetails': self.pcidetails,
            'pcidevices': self.pcidevices,
        }

        with open(filename, 'w') as f:
            json.dump(metadata, f, indent=4, default=JsonSerializable.dumper)

    def writeToFLB(self, output_file):
        self.header.writeToFLB(output_file)
        self.pcidetails.writeToFLB(output_file)
        self.pcidevices.writeToFLB(output_file)
        self.firmware.writeToFLB(output_file)


def extract_firmware(args):
    try:
        os.mkdir(args.output_directory)
    except OSError:
        warning('Output directory exists, writing anyway')

    inputdata = args.input.read()

    if inputdata[0:4] != "FLB3":
        warning('File does not appear to be FLB3, continuing anyway... this is not likely going to work')

    debug("Reading %i bytes..." % len(inputdata))

    all_chunks = []
    pos = 0
    while pos < len(inputdata):
        chunk = FLBChunk(len(all_chunks))
        pos += chunk.parse(inputdata[pos:])
        all_chunks.append(chunk)

    debug('Parsing done, writing %i chunks to disk' % len(all_chunks))

    for chunk in all_chunks:
        chunk.extractToDisk(args.output_directory)

    info('Done!')

# Convert our serialized data back into real objects... probably not the *best* way of doing this, but
# it's simple enough for what we're doing here
def object_hook(curobject):
    if '__classname__' not in curobject:
        return curobject

    if curobject['__classname__'] == 'PCIDetails':
        cur = PCIDetails()
        cur.deserialize(curobject)
        return cur
    elif curobject['__classname__'] == 'FLBHeader':
        cur = FLBHeader()
        cur.deserialize(curobject)
        return cur
    elif curobject['__classname__'] == 'PCIDeviceList':
        cur = PCIDeviceList()
        cur.deserialize(curobject)
        return cur
    elif curobject['__classname__'] == 'PCIDevice':
        del curobject['__classname__']
        cur = PCIDevice(*curobject)
        cur.deserialize(curobject)
        return cur
    else:
        warning('Invalid class name: %s' % curobject['__classname__'])
        return curobject


def write_firmware(args):
    all_chunks = []
    file_list = glob.glob(os.path.join(args.input_directory, '*.bin'))
    file_list.sort()
    for file in file_list:
        debug('-------------------------')
        debug('Processing %s' % file)
        metadata_file = file.replace('.bin', '.json')
        with open(metadata_file, 'r') as f:
            metadata = json.load(f, object_hook=object_hook)

        chunknum = int(os.path.basename(file).replace('.bin', '').replace('chunk_', ''))

        chunk = FLBChunk(chunknum)
        chunk.header = metadata['header']
        chunk.pcidetails = metadata['pcidetails']
        chunk.pcidevices = metadata['pcidevices']

        with open(file, 'rb') as f:
            chunk.firmware = FirmwareData(f.read())

        chunk.recalculateHeaders()

        all_chunks.append(chunk)

    info('Loaded %i chunks' % len(all_chunks))

    for chunk in all_chunks:
        debug('Writing chunk %i' % chunk.chunknum)
        chunk.writeToFLB(args.output)

    info('Done!')

parser = argparse.ArgumentParser(description='Interact with Intel firmware blobs')
parser.add_argument('--debug',action='store_true', help='Output debugging information (like hexdumps)')
subparsers = parser.add_subparsers()

newparser = subparsers.add_parser('extract_firmware', description='Extract all the components of a FLB3 file')
newparser.add_argument('--input', required=True, type=argparse.FileType('rb'), help='FLB3 file to extract')
newparser.add_argument('--output_directory', required=True, help='Path to directory where firmware components will be written')
newparser.set_defaults(func=extract_firmware)

newparser = subparsers.add_parser('write_firmware', description='Merge the contents of a directory into a single FLB3 file')
newparser.add_argument('--input_directory', required=True, help='Path of directory to read firmware components out of')
newparser.add_argument('--output', required=True, type=argparse.FileType('wb'), help='Name of file to write output to')
newparser.set_defaults(func=write_firmware)

args = parser.parse_args()
if args.debug:
    import hexdump
args.func(args)


#!/usr/bin/env python

from __future__ import print_function

"""Bluetooth Low Energy Python interface"""
import sys
import os
import time
import subprocess
import binascii
import select
import struct
import signal
from queue import Queue, Empty
from threading import Thread

def preexec_function():
    # Ignore the SIGINT signal by setting the handler to the standard
    # signal handler SIG_IGN.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

script_path = os.path.join(os.path.abspath(os.path.dirname(__file__)))
helper_exe = os.path.join(script_path, "bluepy-helper")

SEC_LEVEL_LOW = "low"
SEC_LEVEL_MEDIUM = "medium"
SEC_LEVEL_HIGH = "high"

ADDR_TYPE_PUBLIC = "public"
ADDR_TYPE_RANDOM = "random"

debugging = False
def DBG(*args):
    if debugging:
        msg = " ".join([str(a) for a in args])
        print(msg)


class BTLEException(Exception):
    """Base class for all Bluepy exceptions"""
    def __init__(self, message, resp_dict=None):
        self.message = message

        # optional messages from bluepy-helper
        self.estat = None
        self.emsg = None
        if resp_dict:
            self.estat = resp_dict.get('estat',None)
            if isinstance(self.estat,list):
                self.estat = self.estat[0]
            self.emsg = resp_dict.get('emsg',None)
            if isinstance(self.emsg,list):
                self.emsg = self.emsg[0]


    def __str__(self):
        msg = self.message
        if self.estat or self.emsg:
            msg = msg + " ("
            if self.estat:
                msg = msg + "code: %s" % self.estat
            if self.estat and self.emsg:
                msg = msg + ", "
            if self.emsg:
                msg = msg + "error: %s" % self.emsg
            msg = msg + ")"

        return msg

class BTLEInternalError(BTLEException):
    def __init__(self, message, rsp=None):
        BTLEException.__init__(self, message, rsp)

class BTLEDisconnectError(BTLEException):
    def __init__(self, message, rsp=None):
        BTLEException.__init__(self, message, rsp)

class BTLEManagementError(BTLEException):
    def __init__(self, message, rsp=None):
        BTLEException.__init__(self, message, rsp)

class BTLEGattError(BTLEException):
    def __init__(self, message, rsp=None):
        BTLEException.__init__(self, message, rsp)



class UUID:
    def __init__(self, val, common_name=None):
        '''We accept: 32-digit hex strings, with and without '-' characters,
           4 to 8 digit hex strings, and integers'''
        if isinstance(val, int):
            if (val < 0) or (val > 0xFFFFFFFF):
                raise ValueError(
                    "Short form UUIDs must be in range 0..0xFFFFFFFF")
            val = "%04X" % val
        elif isinstance(val, self.__class__):
            val = str(val)
        else:
            val = str(val)  # Do our best

        val = val.replace("-", "")
        if len(val) <= 8:  # Short form
            val = ("0" * (8 - len(val))) + val + "00001000800000805F9B34FB"

        self.bin_val = binascii.a2b_hex(val.encode('utf-8'))
        if len(self.bin_val) != 16:
            raise ValueError(
                "UUID must be 16 bytes, got '%s' (len=%d)" % (val,
                                                              len(self.bin_val)))
        self.common_name = common_name

    def __str__(self):
        s = binascii.b2a_hex(self.bin_val).decode('utf-8')
        return "-".join([s[0:8], s[8:12], s[12:16], s[16:20], s[20:32]])

    def __eq__(self, other):
        return self.bin_val == UUID(other).bin_val

    def __cmp__(self, other):
        return cmp(self.bin_val, UUID(other).bin_val)

    def __hash__(self):
        return hash(self.bin_val)

    def get_common_name(self):
        s = AssignedNumbers.get_common_name(self)
        if s:
            return s
        s = str(self)
        if s.endswith("-0000-1000-8000-00805f9b34fb"):
            s = s[0:8]
            if s.startswith("0000"):
                s = s[4:]
        return s

class Service:
    def __init__(self, *args):
        (self.peripheral, uuid_val, self.handle_start, self.handle_end) = args
        self.uuid = UUID(uuid_val)
        self.chars = None
        self.descs = None

    def get_characteristics(self, for_uuid=None):
        if not self.chars: # Unset, or empty
            self.chars = [] if self.handle_end <= self.handle_start else self.peripheral.get_characteristics(self.handle_start, self.handle_end)
        if for_uuid is not None:
            u = UUID(for_uuid)
            return [ch for ch in self.chars if ch.uuid==u]
        return self.chars

    def get_descriptors(self, for_uuid=None):
        if not self.descs:
            # Grab all descriptors in our range, except for the service
            # declaration descriptor
            all_descs = self.peripheral.get_descriptors(self.handle_start+1, self.handle_end)
            # Filter out the descriptors for the characteristic properties
            # Note that this does not filter out characteristic value descriptors
            self.descs = [desc for desc in all_descs if desc.uuid != 0x2803]
        if for_uuid is not None:
            u = UUID(for_uuid)
            return [desc for desc in self.descs if desc.uuid == u]
        return self.descs

    def __str__(self):
        return "Service <uuid=%s handleStart=%s handleEnd=%s>" % (self.uuid.get_common_name(),
                                                                 self.handle_start,
                                                                 self.handle_end)

class Characteristic:
    # Currently only READ is used in supports_read function,
    # the rest is included to facilitate supportsXXXX functions if required
    props = {"BROADCAST":    0b00000001,
             "READ":         0b00000010,
             "WRITE_NO_RESP":0b00000100,
             "WRITE":        0b00001000,
             "NOTIFY":       0b00010000,
             "INDICATE":     0b00100000,
             "WRITE_SIGNED": 0b01000000,
             "EXTENDED":     0b10000000,
    }

    prop_names = {0b00000001 : "BROADCAST",
                  0b00000010 : "READ",
                  0b00000100 : "WRITE NO RESPONSE",
                  0b00001000 : "WRITE",
                  0b00010000 : "NOTIFY",
                  0b00100000 : "INDICATE",
                  0b01000000 : "WRITE SIGNED",
                  0b10000000 : "EXTENDED PROPERTIES",
    }

    def __init__(self, *args):
        (self.peripheral, uuid_val, self.handle, self.properties, self.val_handle) = args
        self.uuid = UUID(uuid_val)
        self.descs = None

    def read(self):
        return self.peripheral.read_characteristic(self.val_handle)

    def write(self, val, with_response=False):
        return self.peripheral.write_characteristic(self.val_handle, val, with_response)

    def get_descriptors(self, for_uuid=None, handle_end=0xFFFF):
        if not self.descs:
            # Descriptors (not counting the value descriptor) begin after
            # the handle for the value descriptor and stop when we reach
            # the handle for the next characteristic or service
            self.descs = []
            for desc in self.peripheral.get_descriptors(self.val_handle+1, handle_end):
                if desc.uuid in (0x2800, 0x2801, 0x2803):
                    # Stop if we reach another characteristic or service
                    break
                self.descs.append(desc)
        if for_uuid is not None:
            u = UUID(for_uuid)
            return [desc for desc in self.descs if desc.uuid == u]
        return self.descs

    def __str__(self):
        return "Characteristic <%s>" % self.uuid.get_common_name()

    def supports_read(self):
        if (self.properties & Characteristic.props["READ"]):
            return True
        else:
            return False

    def properties_to_string(self):
        prop_str = ""
        for p in Characteristic.prop_names:
           if (p & self.properties):
               prop_str += Characteristic.prop_names[p] + " "
        return prop_str

    def get_handle(self):
        return self.val_handle

class Descriptor:
    def __init__(self, *args):
        (self.peripheral, uuid_val, self.handle) = args
        self.uuid = UUID(uuid_val)

    def __str__(self):
        return "Descriptor <%s>" % self.uuid.get_common_name()
        

    def read(self):
        return self.peripheral.read_characteristic(self.handle)

    def write(self, val, with_response=False):
        self.peripheral.write_characteristic(self.handle, val, with_response)

class DefaultDelegate:
    def __init__(self):
        pass

    def handle_notification(self, c_handle, data):
        DBG("Notification:", c_handle, "sent data", binascii.b2a_hex(data))

    def handle_discovery(self, scan_entry, is_new_dev, is_new_data):
        DBG("Discovered device", scan_entry.addr)

class BluepyHelper:
    def __init__(self):
        self._helper = None
        self._lineq = None
        self._stderr = None
        self._mtu = 0
        self.delegate = DefaultDelegate()

    def with_delegate(self, delegate_):
        self.delegate = delegate_
        return self

    def _start_helper(self, iface=None):
        if self._helper is None:
            DBG("Running ", helper_exe)
            self._lineq = Queue()
            self._mtu = 0
            self._stderr = open(os.devnull, "w")
            args = [helper_exe]
            if iface is not None: args.append(str(iface))
            self._helper = subprocess.Popen(args,
                                            stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE,
                                            stderr=self._stderr,
                                            universal_newlines=True,
                                            preexec_fn = preexec_function)
            t = Thread(target=self._read_to_queue)
            t.daemon = True               # don't wait for it to exit
            t.start()

    def _read_to_queue(self):
        """Thread to read lines from stdout and insert in queue."""
        while self._helper:
            line = self._helper.stdout.readline()
            if not line:                  # EOF
                break
            self._lineq.put(line)

    def _stop_helper(self):
        if self._helper is not None:
            DBG("Stopping ", helper_exe)
            self._helper.stdin.write("quit\n")
            self._helper.stdin.flush()
            self._helper.wait()
            self._helper = None
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None

    def _write_cmd(self, cmd):
        if self._helper is None:
            raise BTLEInternalError("Helper not started (did you call connect()?)")
        DBG("Sent: ", cmd)
        self._helper.stdin.write(cmd)
        self._helper.stdin.flush()

    def _mgmt_cmd(self, cmd):
        self._write_cmd(cmd + '\n')
        rsp = self._wait_resp('mgmt')
        if rsp['code'][0] != 'success':
            self._stop_helper()
            raise BTLEManagementError("Failed to execute management command '%s'" % (cmd), rsp)

    @staticmethod
    def parse_resp(line):
        DBG("Parsing response: ", line)
        resp = {}
        items = line.rstrip().split('\x1e')
        DBG("Items parsed: ", repr(items))
        for item in items:
            (tag, tval) = item.split('=')
            if len(tval)==0:
                val = None
            elif tval[0]=="$" or tval[0]=="'":
                # Both symbols and strings as Python strings
                val = tval[1:]
            elif tval[0]=="h":
                val = int(tval[1:], 16)
            elif tval[0]=='b':
                val = binascii.a2b_hex(tval[1:].encode('utf-8'))
            else:
                raise BTLEInternalError("Cannot understand response value %s" % repr(tval))
            if tag not in resp:
                resp[tag] = [val]
            else:
                resp[tag].append(val)
        DBG("Parsed response: ", repr(resp))
        return resp

    def _wait_resp(self, want_type, timeout=None):
        while True:
            if self._helper.poll() is not None:
                raise BTLEInternalError("Helper exited")

            try:
                rv = self._lineq.get(timeout=timeout)
            except Empty:
                DBG("Select timeout")
                return None

            DBG("Got:", repr(rv))
            if rv.startswith('#') or rv == '\n' or len(rv)==0:
                continue

            resp = BluepyHelper.parse_resp(rv)
            if 'rsp' not in resp:
                raise BTLEInternalError("No response type indicator", resp)

            resp_type = resp['rsp'][0]

            # always check for MTU updates
            if 'mtu' in resp and len(resp['mtu']) > 0:
                new_mtu = int(resp['mtu'][0])
                if self._mtu != new_mtu:
                    self._mtu = new_mtu
                    DBG("Updated MTU: " + str(self._mtu))

            if resp_type in want_type:
                return resp
            elif resp_type == 'stat':
                if 'state' in resp and len(resp['state']) > 0 and resp['state'][0] == 'disc':
                    self._stop_helper()
                    raise BTLEDisconnectError("Device disconnected", resp)
            elif resp_type == 'err':
                errcode=resp['code'][0]
                if errcode=='nomgmt':
                    raise BTLEManagementError("Management not available (permissions problem?)", resp)
                elif errcode=='atterr':
                    raise BTLEGattError("Bluetooth command failed", resp)
                else:
                    raise BTLEException("Error from bluepy-helper (%s)" % errcode, resp)
            elif resp_type == 'scan':
                # Scan response when we weren't interested. Ignore it
                continue
            else:
                raise BTLEInternalError("Unexpected response (%s)" % resp_type, resp)

    def status(self):
        self._write_cmd("stat\n")
        return self._wait_resp(['stat'])


class Peripheral(BluepyHelper):
    def __init__(self, device_addr=None, addr_type=ADDR_TYPE_PUBLIC, iface=None):
        BluepyHelper.__init__(self)
        self._service_map = None # Indexed by UUID
        (self.device_addr, self.addr_type, self.iface) = (None, None, None)

        self.connect(device_addr, addr_type, iface)

    def set_delegate(self, delegate_): # same as with_delegate(), deprecated
        return self.with_delegate(delegate_)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.disconnect()

    def _get_resp(self, want_type, timeout=None):
        if isinstance(want_type, list) is not True:
            want_type = [want_type]

        while True:
            resp = self._wait_resp(want_type + ['ntfy', 'ind'], timeout)
            if resp is None:
                return None

            resp_type = resp['rsp'][0]
            if resp_type == 'ntfy' or resp_type == 'ind':
                hnd = resp['hnd'][0]
                data = resp['d'][0]
                if self.delegate is not None:
                    self.delegate.handle_notification(hnd, data)
            if resp_type not in want_type:
                continue
            return resp

    def _connect(self, addr, addr_type=ADDR_TYPE_PUBLIC, iface=None):
        DBG("Connecting to Peripheral at address: ", addr)
        if len(addr.split(":")) != 6:
            raise ValueError("Expected MAC address, got %s" % repr(addr))
        if addr_type not in (ADDR_TYPE_PUBLIC, ADDR_TYPE_RANDOM):
            raise ValueError("Expected address type public or random, got {}".format(addr_type))
        self._start_helper(iface)
        self.addr = addr
        self.addr_type = addr_type
        self.iface = iface
        if iface is not None:
            self._write_cmd("conn %s %s %s\n" % (addr, addr_type, "hci"+str(iface)))
        else:
            self._write_cmd("conn %s %s\n" % (addr, addr_type))
        rsp = self._get_resp('stat')
        while rsp['state'][0] == 'tryconn':
            rsp = self._get_resp('stat')
        if rsp['state'][0] != 'conn':
            self._stop_helper()
            raise BTLEDisconnectError("Failed to connect to peripheral %s, addr type: %s" % (addr, addr_type), rsp)

    def connect(self, addr, addr_type=ADDR_TYPE_PUBLIC, iface=None):
        if isinstance(addr, ScanEntry):
            self._connect(addr.addr, addr.addr_type, addr.iface)
        elif addr is not None:
            self._connect(addr, addr_type, iface)

    def disconnect(self):
        DBG("Disconnecting from device at address: ", self.device_addr)
        if self._helper is None:
            DBG("Device was already disconnected.")
            return
        # Unregister the delegate first
        self.set_delegate(None)

        self._write_cmd("disc\n")
        self._get_resp('stat')
        self._stop_helper()
        DBG("Device successfully disconnected.")

    def discover_services(self):
        self._write_cmd("svcs\n")
        rsp = self._get_resp('find')
        starts = rsp['hstart']
        ends   = rsp['hend']
        uuids  = rsp['uuid']
        num_services = len(uuids)
        assert(len(starts)==num_services and len(ends)==num_services)
        self._service_map = {}
        for i in range(num_services):
            self._service_map[UUID(uuids[i])] = Service(self, uuids[i], starts[i], ends[i])
        return self._service_map

    def get_state(self):
        status = self.status()
        return status['state'][0]

    @property
    def services(self):
        if self._service_map is None:
            self._service_map = self.discover_services()
        return self._service_map.values()

    def get_services(self):
        return self.services

    def get_service_by_uuid(self, uuid_val):
        uuid = UUID(uuid_val)
        if self._service_map is not None and uuid in self._service_map:
            return self._service_map[uuid]
        self._write_cmd("svcs %s\n" % uuid)
        rsp = self._get_resp('find')
        if 'hstart' not in rsp:
            raise BTLEGattError("Service %s not found" % (uuid.get_common_name()), rsp)
        svc = Service(self, uuid, rsp['hstart'][0], rsp['hend'][0])
        
        if self._service_map is None:
            self._service_map = {}
        self._service_map[uuid] = svc
        return svc

    def _get_included_services(self, start_handle=1, end_handle=0xFFFF):
        # TODO: No working example of this yet
        self._write_cmd("incl %X %X\n" % (start_handle, end_handle))
        return self._get_resp('find')

    def get_characteristics(self, start_handle=1, end_handle=0xFFFF, uuid=None):
        cmd = 'char %X %X' % (start_handle, end_handle)
        if uuid:
            cmd += ' %s' % UUID(uuid)
        self._write_cmd(cmd + "\n")
        rsp = self._get_resp('find')
        nChars = len(rsp['hnd'])
        return [Characteristic(self, rsp['uuid'][i], rsp['hnd'][i],
                               rsp['props'][i], rsp['vhnd'][i])
                for i in range(nChars)]

    def get_descriptors(self, start_handle=1, end_handle=0xFFFF):
        self._write_cmd("desc %X %X\n" % (start_handle, end_handle) )
        # Historical note:
        # Certain Bluetooth LE devices are not capable of sending back all
        # descriptors in one packet due to the limited size of MTU. So the
        # guest needs to check the response and make retries until all handles
        # are returned.
        # In bluez 5.25 and later, gatt_discover_desc() in attrib/gatt.c does the retry
        # so bluetooth_helper always returns a full list.
        # This was broken in earlier versions.
        resp = self._get_resp('desc')
        ndesc = len(resp['hnd'])
        return [Descriptor(self, resp['uuid'][i], resp['hnd'][i]) for i in range(ndesc)]

    def read_characteristic(self, handle):
        self._write_cmd("rd %X\n" % handle)
        resp = self._get_resp('rd')
        return resp['d'][0]

    def _read_characteristic_by_uuid(self, uuid, start_handle, end_handle):
        # Not used at present
        self._write_cmd("rdu %s %X %X\n" % (UUID(uuid), start_handle, end_handle))
        return self._get_resp('rd')

    def write_characteristic(self, handle, val, with_response=False):
        # Without response, a value too long for one packet will be truncated,
        # but with response, it will be sent as a queued write
        cmd = "wrr" if with_response else "wr"
        self._write_cmd("%s %X %s\n" % (cmd, handle, binascii.b2a_hex(val).decode('utf-8')))
        return self._get_resp('wr')

    def set_security_level(self, level):
        self._write_cmd("secu %s\n" % level)
        return self._get_resp('stat')

    def unpair(self):
        self._mgmt_cmd("unpair")

    def pair(self):
        self._mgmt_cmd("pair")

    def getMTU(self):
        return self._mtu

    def setMTU(self, mtu):
        self._write_cmd("mtu %x\n" % mtu)
        return self._get_resp('stat')

    def wait_for_notifications(self, timeout):
         resp = self._get_resp(['ntfy','ind'], timeout)
         return (resp != None)

    def _set_remote_oob(self, address, address_type, oob_data, iface=None):
        if self._helper is None:
            self._start_helper(iface)
        self.addr = address
        self.addr_type = address_type
        self.iface = iface
        cmd = "remote_oob " + address + " " + address_type
        if oob_data['C_192'] is not None and oob_data['R_192'] is not None:
            cmd += " C_192 " + oob_data['C_192'] + " R_192 " + oob_data['R_192']
        if oob_data['C_256'] is not None and oob_data['R_256'] is not None:
            cmd += " C_256 " + oob_data['C_256'] + " R_256 " + oob_data['R_256']
        if iface is not None:
            cmd += " hci"+str(iface)
        self._write_cmd(cmd)

    def set_remote_oob(self, address, address_type, oob_data, iface=None):
        if len(address.split(":")) != 6:
            raise ValueError("Expected MAC address, got %s" % repr(address))
        if address_type not in (ADDR_TYPE_PUBLIC, ADDR_TYPE_RANDOM):
            raise ValueError("Expected address type public or random, got {}".format(address_type))
        if isinstance(address, ScanEntry):
            return self._setOOB(address.addr, address.addr_type, oob_data, address.iface)
        elif address is not None:
            return self._set_remote_oob(address, address_type, oob_data, iface)

    def get_local_oob(self, iface=None):
        if self._helper is None:
            self._start_helper(iface)
        self.iface = iface
        self._write_cmd("local_oob\n")
        if iface is not None:
            cmd += " hci"+str(iface)
        resp = self._get_resp('oob')
        if resp is not None:
            data = resp.get('d', [''])[0]
            if data is None:
                raise BTLEManagementError(
                                "Failed to get local OOB data.")
            if struct.unpack_from('<B',data,0)[0] != 8 or struct.unpack_from('<B',data,1)[0] != 0x1b:
                raise BTLEManagementError(
                                "Malformed local OOB data (address).")
            address = data[2:8]
            address_type = data[8:9]
            if struct.unpack_from('<B',data,9)[0] != 2 or struct.unpack_from('<B',data,10)[0] != 0x1c:
                raise BTLEManagementError(
                                "Malformed local OOB data (role).")
            role = data[11:12]
            if struct.unpack_from('<B',data,12)[0] != 17 or struct.unpack_from('<B',data,13)[0] != 0x22:
                raise BTLEManagementError(
                                "Malformed local OOB data (confirm).")
            confirm = data[14:30]
            if struct.unpack_from('<B',data,30)[0] != 17 or struct.unpack_from('<B',data,31)[0] != 0x23:
                raise BTLEManagementError(
                                "Malformed local OOB data (random).")
            random = data[32:48]
            if struct.unpack_from('<B',data,48)[0] != 2 or struct.unpack_from('<B',data,49)[0] != 0x1:
                raise BTLEManagementError(
                                "Malformed local OOB data (flags).")
            flags = data[50:51]
            return {'Address' : ''.join(["%02X" % struct.unpack('<B',c)[0] for c in address]),
                    'Type' : ''.join(["%02X" % struct.unpack('<B',c)[0] for c in address_type]),
                    'Role' : ''.join(["%02X" % struct.unpack('<B',c)[0] for c in role]),
                    'C_256' : ''.join(["%02X" % struct.unpack('<B',c)[0] for c in confirm]),
                    'R_256' : ''.join(["%02X" % struct.unpack('<B',c)[0] for c in random]),
                    'Flags' : ''.join(["%02X" % struct.unpack('<B',c)[0] for c in flags]),
                    }

    def __del__(self):
        self.disconnect()

class ScanEntry:
    addr_types = { 1 : ADDR_TYPE_PUBLIC,
                   2 : ADDR_TYPE_RANDOM
                 }

    FLAGS                     = 0x01
    INCOMPLETE_16B_SERVICES   = 0x02
    COMPLETE_16B_SERVICES     = 0x03
    INCOMPLETE_32B_SERVICES   = 0x04
    COMPLETE_32B_SERVICES     = 0x05
    INCOMPLETE_128B_SERVICES  = 0x06
    COMPLETE_128B_SERVICES    = 0x07
    SHORT_LOCAL_NAME          = 0x08
    COMPLETE_LOCAL_NAME       = 0x09
    TX_POWER                  = 0x0A
    SERVICE_SOLICITATION_16B  = 0x14
    SERVICE_SOLICITATION_32B  = 0x1F
    SERVICE_SOLICITATION_128B = 0x15
    SERVICE_DATA_16B          = 0x16
    SERVICE_DATA_32B          = 0x20
    SERVICE_DATA_128B         = 0x21
    PUBLIC_TARGET_ADDRESS     = 0x17
    RANDOM_TARGET_ADDRESS     = 0x18
    APPEARANCE                = 0x19
    ADVERTISING_INTERVAL      = 0x1A
    MANUFACTURER              = 0xFF

    data_tags = {
        FLAGS                     : 'Flags',
        INCOMPLETE_16B_SERVICES   : 'Incomplete 16b Services',
        COMPLETE_16B_SERVICES     : 'Complete 16b Services',
        INCOMPLETE_32B_SERVICES   : 'Incomplete 32b Services',
        COMPLETE_32B_SERVICES     : 'Complete 32b Services',
        INCOMPLETE_128B_SERVICES  : 'Incomplete 128b Services',
        COMPLETE_128B_SERVICES    : 'Complete 128b Services',
        SHORT_LOCAL_NAME          : 'Short Local Name',
        COMPLETE_LOCAL_NAME       : 'Complete Local Name',
        TX_POWER                  : 'Tx Power',
        SERVICE_SOLICITATION_16B  : '16b Service Solicitation',
        SERVICE_SOLICITATION_32B  : '32b Service Solicitation',
        SERVICE_SOLICITATION_128B : '128b Service Solicitation',
        SERVICE_DATA_16B          : '16b Service Data',
        SERVICE_DATA_32B          : '32b Service Data',
        SERVICE_DATA_128B         : '128b Service Data',
        PUBLIC_TARGET_ADDRESS     : 'Public Target Address',
        RANDOM_TARGET_ADDRESS     : 'Random Target Address',
        APPEARANCE                : 'Appearance',
        ADVERTISING_INTERVAL      : 'Advertising Interval',
        MANUFACTURER              : 'Manufacturer',
    }

    def __init__(self, addr, iface):
        self.addr = addr
        self.iface = iface
        self.addr_type = None
        self.rssi = None
        self.connectable = False
        self.raw_data = None
        self.scan_data = {}
        self.update_count = 0

    def _update(self, resp):
        addr_type = self.addr_types.get(resp['type'][0], None)
        if (self.addr_type is not None) and (addr_type != self.addr_type):
            raise BTLEInternalError("Address type changed during scan, for address %s" % self.addr)
        self.addr_type = addr_type
        self.rssi = -resp['rssi'][0]
        self.connectable = ((resp['flag'][0] & 0x4) == 0)
        data = resp.get('d', [''])[0]
        self.raw_data = data
        
        # Note: bluez is notifying devices twice: once with advertisement data,
        # then with scan response data. Also, the device may update the
        # advertisement or scan data
        is_new_data = False
        while len(data) >= 2:
            sdlen, sdid = struct.unpack_from('<BB', data)
            val = data[2 : sdlen + 1]
            if (sdid not in self.scan_data) or (val != self.scan_data[sdid]):
                is_new_data = True
            self.scan_data[sdid] = val
            data = data[sdlen + 1:]

        self.update_count += 1
        return is_new_data
     
    def _decode_uuid(self, val, nbytes):
        if len(val) < nbytes:
            return None
        bval=bytearray(val)
        rs=""
        # Bytes are little-endian; convert to big-endian string
        for i in range(nbytes):
            rs = ("%02X" % bval[i]) + rs
        return UUID(rs)

    def _decode_uuid_list(self, val, nbytes):
        result = []
        for i in range(0, len(val), nbytes):
            if len(val) >= (i+nbytes):
                result.append(self._decode_uuid(val[i:i+nbytes],nbytes))
        return result
    
    def get_description(self, sdid):
        return self.data_tags.get(sdid, hex(sdid))

    def get_value(self, sdid):
        val = self.scan_data.get(sdid, None)
        if val is None:
            return None
        if sdid in [ScanEntry.SHORT_LOCAL_NAME, ScanEntry.COMPLETE_LOCAL_NAME]:
            try:
                # Beware! Vol 3 Part C 18.3 doesn't give an encoding. Other references
                # to 'local name' (e.g. vol 3 E, 6.23) suggest it's UTF-8 but in practice
                # devices sometimes have garbage here. See #259, #275, #292.
                return val.decode('utf-8')
            except UnicodeDecodeError:
                bbval = bytearray(val)
                return ''.join( [ (chr(x) if (x>=32 and x<=127) else '?') for x in bbval ] )
        elif sdid in [ScanEntry.INCOMPLETE_16B_SERVICES, ScanEntry.COMPLETE_16B_SERVICES]:
            return self._decode_uuid_list(val,2)
        elif sdid in [ScanEntry.INCOMPLETE_32B_SERVICES, ScanEntry.COMPLETE_32B_SERVICES]:
            return self._decode_uuid_list(val,4)
        elif sdid in [ScanEntry.INCOMPLETE_128B_SERVICES, ScanEntry.COMPLETE_128B_SERVICES]:
            return self._decode_uuid_list(val,16)
        else:
            return val

    def get_value_text(self, sdid):
        val = self.get_value(sdid)
        if val is None:
            return None
        if sdid in [ScanEntry.SHORT_LOCAL_NAME, ScanEntry.COMPLETE_LOCAL_NAME]:
            return val
        elif isinstance(val, list):
            return ','.join(str(v) for v in val)
        else:
            return binascii.b2a_hex(val).decode('ascii')
    
    def get_scan_data(self):
        '''Returns list of tuples [(tag, description, value)]'''
        return [ (sdid, self.get_description(sdid), self.get_value_text(sdid))
                    for sdid in self.scan_data.keys() ]
         
 
class Scanner(BluepyHelper):
    def __init__(self,iface=0):
        BluepyHelper.__init__(self)
        self.scanned = {}
        self.iface=iface
        self.passive=False
    
    def _cmd(self):
        return "pasv" if self.passive else "scan"

    def start(self, passive=False):
        self.passive = passive
        self._start_helper(iface=self.iface)
        self._mgmt_cmd("le on")
        self._write_cmd(self._cmd()+"\n")
        rsp = self._wait_resp("mgmt")
        if rsp["code"][0] == "success":
            return
        # Sometimes previous scan still ongoing
        if rsp["code"][0] == "busy":
            self._mgmt_cmd(self._cmd()+"end")
            rsp = self._wait_resp("stat")
            assert rsp["state"][0] == "disc"
            self._mgmt_cmd(self._cmd())

    def stop(self):
        self._mgmt_cmd(self._cmd()+"end")
        self._stop_helper()

    def clear(self):
        self.scanned = {}

    def process(self, timeout=10.0):
        if self._helper is None:
            raise BTLEInternalError(
                                "Helper not started (did you call start()?)")
        start = time.time()
        while True:
            if timeout:
                remain = start + timeout - time.time()
                if remain <= 0.0: 
                    break
            else:
                remain = None
            resp = self._wait_resp(['scan', 'stat'], remain)
            if resp is None:
                break

            resp_type = resp['rsp'][0]
            if resp_type == 'stat':
                # if scan ended, restart it
                if resp['state'][0] == 'disc':
                    self._mgmt_cmd(self._cmd())

            elif resp_type == 'scan':
                # device found
                addr = binascii.b2a_hex(resp['addr'][0]).decode('utf-8')
                addr = ':'.join([addr[i:i+2] for i in range(0,12,2)])
                if addr in self.scanned:
                    dev = self.scanned[addr]
                else:
                    dev = ScanEntry(addr, self.iface)
                    self.scanned[addr] = dev
                is_new_data = dev._update(resp)
                if self.delegate is not None:
                    self.delegate.handle_discovery(dev, (dev.update_count <= 1), is_new_data)
                 
            else:
                raise BTLEInternalError("Unexpected response: " + resp_type, resp)

    def get_devices(self):
        return self.scanned.values()

    def scan(self, timeout=10, passive=False):
        self.clear()
        self.start(passive=passive)
        self.process(timeout)
        self.stop()
        return self.get_devices()


def capitalise_name(descr):
    words = descr.replace("("," ").replace(")"," ").replace('-',' ').split(" ")
    cap_words =  [ words[0].lower() ]
    cap_words += [ w[0:1].upper() + w[1:].lower() for w in words[1:] ]
    return "".join(cap_words)

class _UUIDNameMap:
    # Constructor sets self.currentTimeService, self.txPower, and so on
    # from names.
    def __init__(self, id_list):
        self.id_map = {}

        for uuid in id_list:
            attr_name = capitalise_name(uuid.common_name)
            vars(self) [attr_name] = uuid
            self.id_map[uuid] = uuid

    def get_common_name(self, uuid):
        if uuid in self.id_map:
            return self.id_map[uuid].common_name
        return None

def get_json_uuid():
    import json
    with open(os.path.join(script_path, 'uuids.json'),"rb") as fp:
        uuid_data = json.loads(fp.read().decode("utf-8"))
    for k in uuid_data.keys():
        for number,cname,name in uuid_data[k]:
            yield UUID(number, cname)
            yield UUID(number, name)

AssignedNumbers = _UUIDNameMap( get_json_uuid() )

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit("Usage:\n  %s <mac-address> [random]" % sys.argv[0])

    if not os.path.isfile(helper_exe):
        raise ImportError("Cannot find required executable '%s'" % helper_exe)

    dev_addr = sys.argv[1]
    if len(sys.argv) == 3:
        addr_type = sys.argv[2]
    else:
        addr_type = ADDR_TYPE_PUBLIC
    print("Connecting to: {}, address type: {}".format(dev_addr, addr_type))
    conn = Peripheral(dev_addr, addr_type)
    try:
        for svc in conn.services:
            print(str(svc), ":")
            for ch in svc.get_characteristics():
                print("    {}, hnd={}, supports {}".format(ch, hex(ch.handle), ch.properties_to_string()))
                chName = AssignedNumbers.get_common_name(ch.uuid)
                if (ch.supports_read()):
                    try:
                        print("    ->", repr(ch.read()))
                    except BTLEException as e:
                        print("    ->", e)

    finally:
        conn.disconnect()

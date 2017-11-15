# Copyright 2017 Joel Fernandes <joelaf@google.com>
# Module to establish and maintain a remote connection
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import base64
from shell import ShellRemote

def get_remote_cls(cls_name):
    cls_name = cls_name.capitalize() + 'Remote'
    cls = globals()[cls_name]
    return cls

class LibRemote(object):
    def __init__(self, remote_name, remote_arg=None):
        # Get the <class>Remote class object
        cls = get_remote_cls(remote_name)

        # Create the remote connection
        self.remote = cls(remote_arg)

    def available_filter_functions(self, tracefs):
        cmd = "GET_AVAIL_FILTER_FUNCS {}".format(tracefs)
        return self.remote.send_command(cmd)

    def kprobes_blacklist(self, tracefs):
        cmd = "GET_KPROBES_BLACKLIST {}".format(tracefs)
        return self.remote.send_command(cmd)

    def bpf_prog_load(self, prog_type, func_str, license_str, kern_version):
        func_str_b64 = base64.b64encode(func_str)
        cmd = "BPF_PROG_LOAD {} {} {} {} {}".format(prog_type, len(func_str),
              license_str, kern_version, base64.b64encode(func_str))
        return self.remote.send_command(cmd)

    def bpf_create_map(self, map_type, key_size, leaf_size, max_entries,
                       flags):
        cmd = "BPF_CREATE_MAP {} {} {} {} {}".format(map_type, key_size,
                                    leaf_size, max_entries, flags)
        return self.remote.send_command(cmd)

# Test
# libremote = LibRemote('shell')


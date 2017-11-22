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
import re
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

    def _remote_send_command(self, cmd):
        """
        Return: a tuple containing return code and output list.
        """
        ret = self.remote.send_command(cmd)
        if not ret:
            return (-1, [])

        if ret[0].startswith('Command not recognized'):
            print('Command not recognized! cmd: {}'.format(cmd))
            return (-1, [])

        # Assume success if first list element doesn't have ret=
        if not 'ret=' in ret[0]:
            return (0, ret)

        m = re.search("ret=(\d+)", ret[0])
        if m == None:
            print('Bad return string for cmd {}'.format(cmd))
            return (-1, [])

        return (int(m.group(1)), ret)

    def available_filter_functions(self, tracefs):
        cmd = "GET_AVAIL_FILTER_FUNCS {}".format(tracefs)
        ret = self._remote_send_command(cmd)
        return ret[0] if ret[0] < 0 else ret[1]

    def kprobes_blacklist(self, tracefs):
        cmd = "GET_KPROBES_BLACKLIST {}".format(tracefs)
        ret = self._remote_send_command(cmd)
        return ret[0] if ret[0] < 0 else ret[1]

    def get_trace_events(self, tracefs, cat):
        cmd = "GET_TRACE_EVENTS {} {}".format(tracefs, cat)
        ret = self._remote_send_command(cmd)
        return ret[0] if ret[0] < 0 else ret[1]

    def get_trace_events_categories(self, tracefs):
        cmd = "GET_TRACE_EVENTS_CATEGORIES {}".format(tracefs)
        ret = self._remote_send_command(cmd)
        return ret[0] if ret[0] < 0 else ret[1]

    def bpf_attach_tracepoint(self, fd, cat, tpname, pid, cpu, gfd):
        cmd = "BPF_ATTACH_TRACEPOINT {} {} {} {} {} {}".format(fd,
            cat, tpname, pid, cpu, gfd)
        ret = self._remote_send_command(cmd)
        return ret[0]

    def bpf_attach_kprobe(self, fd, t, evname, fnname, pid, cpu, gfd):
        cmd = "BPF_ATTACH_KPROBE {} {} {} {} {} {} {}".format(fd, t,
            evname, fnname, pid, cpu, gfd)
        ret = self._remote_send_command(cmd)
        return ret[0]

    def bpf_prog_load(self, prog_type, func_str, license_str, kern_version):
        func_str_b64 = base64.b64encode(func_str)
        cmd = "BPF_PROG_LOAD {} {} {} {} {}".format(prog_type, len(func_str),
              license_str, kern_version, base64.b64encode(func_str))
        ret = self._remote_send_command(cmd)
        return ret[0]

    def bpf_create_map(self, map_type, key_size, leaf_size, max_entries,
                       flags):
        cmd = "BPF_CREATE_MAP {} {} {} {} {}".format(map_type, key_size,
                                    leaf_size, max_entries, flags)
        ret = self._remote_send_command(cmd)
        return ret[0]

    def bpf_update_elem(self, map_fd, kstr, klen, lstr, llen, flags):
        cmd = "BPF_UPDATE_ELEM {} {} {} {} {} {}".format(map_fd, kstr, klen,
                                                         lstr, llen, flags)
        ret = self._remote_send_command(cmd)
        return ret[0]

    def bpf_lookup_elem(self, map_fd, kstr, klen, llen):
        cmd = "BPF_LOOKUP_ELEM {} {} {} {}".format(map_fd, kstr, klen, llen)
        ret = self._remote_send_command(cmd)
        return ret[0] if ret[0] < 0 else ret[1]

    def bpf_open_perf_buffer(self, pid, cpu, page_cnt):
        cmd = "BPF_OPEN_PERF_BUFFER {} {} {}".format(pid, cpu, page_cnt)
        ret = self._remote_send_command(cmd)
        return ret[0]

    def close_connection(self):
        self._remote_send_command("exit")
        self.remote.close_connection()

# Test
# libremote = LibRemote('shell')


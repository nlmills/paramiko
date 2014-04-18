# Copyright (C) 2014  Nicholas Mills <nlmills@g.clemson.edu>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

import os.path
import socket
import subprocess

import paramiko
import paramiko.py3compat


class Keysign(object):

    def __init__(self, keysign_path=''):
        candidate_paths = [keysign_path,
                           '/usr/libexec/ssh-keysign',
                           '/usr/libexec/openssh/ssh-keysign']

        match = None
        for path in candidate_paths:
            if os.path.isfile(path):
                match = path
                break

        if match is None:
            raise Exception('no ssh-keysign program found')
        self._keysign_path = match

    def sign(self, blob):
        version = paramiko.py3compat.byte_chr(2)

        ksproc = subprocess.Popen([self._keysign_path],
                                  stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE)
        request = paramiko.Message()
        request.add_byte(version)
        request.add_int(ksproc.stdin.fileno())
        request.add_string(blob)
        reqm = paramiko.Message()
        reqm.add_string(request)

        respm = paramiko.Message(ksproc.communicate(reqm.asbytes())[0])
        response = paramiko.Message(respm.get_string())
        respver = response.get_byte()
        assert respver == version

        signature = response.get_string()
        return signature

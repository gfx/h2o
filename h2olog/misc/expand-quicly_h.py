#!/usr/bin/env python3
#
# Copyright (c) 2019-2020 Fastly, Inc., Toru Maesaka, Goro Fuji
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

# usage: expand-quicly_h.py in_file out_file < quicly_h_content

import sys
import subprocess

(_, in_file, out_file, cpp_command) = sys.argv

quicly_h = subprocess.run(cpp_command, shell=True, check=True, stdout=subprocess.PIPE, universal_newlines=True).stdout

with open(in_file, "r") as infh:
  with open(out_file, "w") as outfh:
    for lineno, line in enumerate(infh):
      if '#include <quicly.h>' in line:
        outfh.write("/* quicly.h - start */\n")
        outfh.write(quicly_h)
        outfh.write("/* quicly.h - end */\n")
      else:
        outfh.write(line)


(*
 * unix_syscalls.ml
 *
 * Stubs for unix syscalls
 *
 * Copyright (C) 2017  Wei Liu <wei.liu2@citrix.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License, version 2.1, as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 *)

type utsname = {
  sysname:  string;
  nodename: string;
  release:  string;
  version:  string;
  machine:  string;
}

external uname : unit -> utsname = "unix_uname"

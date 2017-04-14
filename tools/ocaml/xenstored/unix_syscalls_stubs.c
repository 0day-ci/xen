/*
 * unix_syscalls_stub.c
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
 */

#include <sys/utsname.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/alloc.h>
#include <caml/signals.h>
#include <caml/unixsupport.h>

CAMLprim value unix_uname(value ignored)
{
	CAMLparam1(ignored);
	CAMLlocal1(utsname);
	struct utsname buf;

	if (uname(&buf))
		uerror("uname", Nothing);

	utsname = caml_alloc(5, 0);
	Store_field(utsname, 0, caml_copy_string(buf.sysname));
	Store_field(utsname, 1, caml_copy_string(buf.nodename));
	Store_field(utsname, 2, caml_copy_string(buf.release));
	Store_field(utsname, 3, caml_copy_string(buf.version));
	Store_field(utsname, 4, caml_copy_string(buf.machine));

	CAMLreturn(utsname);
}

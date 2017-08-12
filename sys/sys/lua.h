/*	$NetBSD: lua.h,v 1.8 2015/09/06 06:01:02 dholland Exp $ */

/*
 * Copyright (c) 2017 by Pedro Tammela
 * Copyright (c) 2014 by Lourival Vieira Neto <lneto@NetBSD.org>.
 * Copyright (c) 2011, 2013 Marc Balmer <mbalmer@NetBSD.org>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the Author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SYS_LUA_H_
#define _SYS_LUA_H_

#include <sys/param.h>
#include <sys/ioccom.h>

#include <lua.h>		/* for lua_State */

#ifdef _KERNEL
#include <sys/condvar.h>
#endif

#define MAX_LUA_NAME		32

struct klua_Iowr {
	char	state[MAX_LUA_NAME];
	char	str[MAXPATHLEN];
};

struct info {
	char name[MAX_LUA_NAME];
	size_t len;
};

struct klua_Info {
	int n;
	struct info *i;
};

/* loading Lua code into a Lua state */
#define LUALOAD		_IOWR('l', 0, struct klua_Iowr)

/* creating a Lua state */
#define LUACREATE       _IOWR('l', 1, struct klua_Iowr)

/* destroying a Lua state */
#define LUADESTROY      _IOWR('l', 2, struct klua_Iowr)

/* information about the Lua states */
#define LUAINFO		_IOWR('l', 3, struct klua_Info)

#ifdef _KERNEL
extern int klua_mod_register(const char *, lua_CFunction);
extern int klua_mod_unregister(const char *);

struct klua_Wrapper {
	kmutex_t mtx;
};

extern int klua_state_register(const char *);
extern int klua_state_unregister(const char *);

extern void *lua_alloc(void *, void *, size_t, size_t);

/* C API */
extern lua_State *luaL_newstate(void);

#endif

#define luaK_setenv(L, env, type)			\
do {							\
	type **p = (type **)lua_getextraspace(L);	\
	*p = env;					\
} while (0)						\

#define luaK_getenv(L, type) ((type *)lua_getextraspace(L))

#endif /* _SYS_LUA_H_ */

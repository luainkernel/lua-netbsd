/*	$NetBSD: lua.c,v 1.23 2017/05/20 09:46:17 mbalmer Exp $ */

/*
 * Copyright (c) 2017 by Pedro Tammela
 * Copyright (c) 2011 - 2017 by Marc Balmer <mbalmer@NetBSD.org>.
 * Copyright (c) 2014 by Lourival Vieira Neto <lneto@NetBSD.org>.
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

/* Lua device driver */

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/condvar.h>
#include <sys/device.h>
#include <sys/ioctl.h>
#include <sys/kmem.h>
#include <sys/lock.h>
#include <sys/lua.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/cpu.h>
#include <sys/fcntl.h>

#include <lua.h>
#include <lauxlib.h>

struct lua_softc {
	device_t		 sc_dev;

	kmutex_t		 sc_lock;
	kcondvar_t		 sc_inuse_cv;
	bool			 sc_inuse;

	/* Locking access to state queues */
	kmutex_t		 sc_state_lock;
	kcondvar_t		 sc_state_cv;
	bool			 sc_state;

	struct sysctllog	*sc_log;
};

static device_t	sc_self = NULL;
static bool	bytecode_on = false;
static bool	verbose_mode = false;

static int lua_match(device_t, cfdata_t, void *);
static void lua_attach(device_t, device_t, void *);
static int lua_detach(device_t, int);
static int check_kmod(const char *);


CFATTACH_DECL_NEW(lua, sizeof(struct lua_softc),
	lua_match, lua_attach, lua_detach, NULL);

static kmutex_t drivermtx;
static lua_State *drvL;

dev_type_open(luaopen);
dev_type_close(luaclose);
dev_type_ioctl(luaioctl);

const struct cdevsw lua_cdevsw = {
	.d_open = luaopen,
	.d_close = luaclose,
	.d_read = noread,
	.d_write = nowrite,
	.d_ioctl = luaioctl,
	.d_stop = nostop,
	.d_tty = notty,
	.d_poll = nopoll,
	.d_mmap = nommap,
	.d_kqfilter = nokqfilter,
	.d_discard = nodiscard,
	.d_flag = D_OTHER | D_MPSAFE
};

extern struct cfdriver lua_cd;

static int
lua_match(device_t parent, cfdata_t match, void *aux)
{
	return 1;
}

static void
lua_attach(device_t parent, device_t self, void *aux)
{
	struct lua_softc *sc;
	const struct sysctlnode *node;

	if (sc_self)
		return;

	sc = device_private(self);
	sc->sc_dev = self;
	sc_self = self;

	mutex_init(&sc->sc_lock, MUTEX_DEFAULT, IPL_VM);
	cv_init(&sc->sc_inuse_cv, "luactl");

	mutex_init(&sc->sc_state_lock, MUTEX_DEFAULT, IPL_VM);
	cv_init(&sc->sc_state_cv, "luastate");

	if (!pmf_device_register(self, NULL, NULL))
		aprint_error_dev(self, "couldn't establish power handler\n");

	/* Sysctl to provide some control over behaviour */
        sysctl_createv(&sc->sc_log, 0, NULL, &node,
            CTLFLAG_OWNDESC,
            CTLTYPE_NODE, "lua",
            SYSCTL_DESCR("Lua options"),
            NULL, 0, NULL, 0,
            CTL_KERN, CTL_CREATE, CTL_EOL);

        if (node == NULL) {
		aprint_error(": can't create sysctl node\n");
                return;
	}

        sysctl_createv(&sc->sc_log, 0, &node, NULL,
            CTLFLAG_READWRITE | CTLFLAG_OWNDESC,
            CTLTYPE_BOOL, "bytecode",
            SYSCTL_DESCR("Enable loading of bytecode"),
            NULL, 0, &bytecode_on, 0,
	    CTL_CREATE, CTL_EOL);

        sysctl_createv(&sc->sc_log, 0, &node, NULL,
            CTLFLAG_READWRITE | CTLFLAG_OWNDESC,
            CTLTYPE_BOOL, "verbose",
            SYSCTL_DESCR("Enable verbose output"),
            NULL, 0, &verbose_mode, 0,
	    CTL_CREATE, CTL_EOL);

	aprint_normal_dev(self, "%s\n", LUA_COPYRIGHT);
}

static int
lua_detach(device_t self, int flags)
{
	struct lua_softc *sc;

	sc = device_private(self);
	pmf_device_deregister(self);

	if (sc->sc_log != NULL) {
		sysctl_teardown(&sc->sc_log);
		sc->sc_log = NULL;
	}

	lua_getfield(drvL, LUA_REGISTRYINDEX, "states");
	lua_pushnil(drvL);
	while (lua_next(drvL, -2) != 0) {
		lua_close(lua_touserdata(drvL, -1));
		lua_pop(drvL, 1);
	}
	lua_getfield(drvL, LUA_REGISTRYINDEX, "kmod_cache");
	lua_pushnil(drvL);
	while (lua_next(drvL, -2) != 0) {
		module_unload(lua_tostring(drvL, -2));
		lua_pop(drvL, 1);
	}
	lua_close(drvL);
	mutex_destroy(&sc->sc_lock);
	cv_destroy(&sc->sc_inuse_cv);
	mutex_destroy(&sc->sc_state_lock);
	cv_destroy(&sc->sc_state_cv);
	sc_self = NULL;
	return 0;
}

int
luaopen(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct lua_softc *sc;
	int error = 0;

	if (minor(dev) > 0)
		return ENXIO;

	sc = device_lookup_private(&lua_cd, minor(dev));
	if (sc == NULL)
		return ENXIO;

	mutex_enter(&sc->sc_lock);
	while (sc->sc_inuse == true) {
		error = cv_wait_sig(&sc->sc_inuse_cv, &sc->sc_lock);
		if (error)
			break;
	}
	if (!error)
		sc->sc_inuse = true;
	mutex_exit(&sc->sc_lock);

	if (error)
		return error;
	return 0;
}

int
luaclose(dev_t dev, int flag, int mode, struct lwp *l)
{
	struct lua_softc *sc;

	if (minor(dev) > 0)
		return ENXIO;
	sc = device_lookup_private(&lua_cd, minor(dev));
	mutex_enter(&sc->sc_lock);
	sc->sc_inuse = false;
	cv_signal(&sc->sc_inuse_cv);
	mutex_exit(&sc->sc_lock);
	return 0;
}

static lua_State *
findstate(const char *name)
{
	void *state = NULL;

	mutex_enter(&drivermtx);
	lua_getfield(drvL, LUA_REGISTRYINDEX, "states");
	if (lua_getfield(drvL, -1, name) == LUA_TLIGHTUSERDATA) {
		state = lua_touserdata(drvL, -1);
		lua_pop(drvL, 3);
	}
	mutex_exit(&drivermtx);
	return state;
}

static inline void
fillbuffer(luaL_Buffer *b, struct uio *data)
{
	int i;

	for (i = 0; i < data->uio_iovcnt; i++, data->uio_iov++)
           luaL_addlstring(b, data->uio_iov->iov_base, data->uio_iov->iov_len);
}

int
luaioctl(dev_t dev, u_long cmd, void *data, int flag, struct lwp *l)
{
	struct klua_Info *usrinfo;
	struct klua_Iowr *usrdata;
	struct klua_Wrapper *sw;
	struct lua_softc *sc;
	struct vnode *v;
	struct uio script; /* lua script */
	kauth_cred_t cred;
	luaL_Buffer b;
	lua_State *L;
	int err, n;
	const char *str;
	size_t len;

	UIO_SETUP_SYSSPACE(&script);
	sc = device_lookup_private(&lua_cd, minor(dev));
	if (!device_is_active(sc->sc_dev))
		return EBUSY;

	cred = kauth_cred_get();
	switch (cmd) {
	case LUAINFO:
		usrinfo = data;

		if (usrinfo->i = NULL) {
			lua_getfield(drvL, LUA_REGISTRYINDEX, "states");
			lua_getfield(drvL, -1, "size");
			usrinfo->n = lua_tointeger(drvL, -1);
			lua_pop(drvL, 3);
		} else {
			n = 0;
			lua_getfield(drvL, LUA_REGISTRYINDEX, "states");
			lua_pushnil(drvL);
			while (lua_next(drvL, 1)) {
				/* keys are always strings */
				str = lua_tolstring(drvL, -2, &len);
				copyoutstr(str, usrinfo->i[n].name, len, NULL);
				copyout(&len, &usrinfo->i[n].len, sizeof(size_t));
				n++;
				lua_pop(drvL, 1);
			}
			lua_pop(drvL, 1);
		}

		break;
	case LUACREATE:
		usrdata = data;

		L = luaL_newstate();
		if (L == NULL)
			return ENOMEM;
		if (*usrdata->str == '_') {
			if (verbose_mode)
				aprint_error_dev(sc_self, "names of user "
					"created states must not begin with '_'");
			return ENXIO;
		}
		sw = kmem_intr_alloc(sizeof(struct klua_Wrapper), KM_SLEEP);
		mutex_init(&sw->mtx, MUTEX_DEFAULT, IPL_NONE);
		luaK_setenv(L, sw, struct klua_Wrapper);

		mutex_enter(&drivermtx);
		lua_getfield(drvL, LUA_REGISTRYINDEX, "states");
		lua_pushlightuserdata(drvL, L);
		lua_setfield(drvL, -2, usrdata->state);
		lua_getfield(drvL, -1, "size");
		lua_pushinteger(drvL, (lua_tointeger(L, -1)) + 1);
		lua_setfield(drvL, -3, "size");
		lua_pop(drvL, 2);
		mutex_exit(&drivermtx);

		break;
	case LUADESTROY:
		usrdata = data;

		mutex_enter(&drivermtx);
		lua_getfield(drvL, LUA_REGISTRYINDEX, "states");
		if (lua_getfield(drvL, -1, usrdata->state) != LUA_TLIGHTUSERDATA) {
			if (verbose_mode)
				aprint_error_dev(sc_self, "%s doesn't exist",
						usrdata->state);
			return ENXIO;
		}
		L = lua_touserdata(drvL, -1);
		if (L == NULL)
			return EINVAL;
		lua_pop(drvL, 1);
		lua_pushnil(drvL);
		lua_setfield(drvL, -1, usrdata->state);
		lua_getfield(drvL, -1, "size");
		n = lua_tointeger(L, -1);
		lua_pushinteger(drvL, n--);
		lua_setfield(drvL, -3, "size");
		lua_pop(drvL, 2);
		mutex_exit(&drivermtx);

		sw = luaK_getenv(L, struct klua_Wrapper);

		mutex_enter(&sw->mtx);
		lua_close(L);
		mutex_exit(&sw->mtx);

		mutex_destroy(&sw->mtx);
		kmem_intr_free(sw, sizeof(struct klua_Wrapper));

		break;
	case LUALOAD:
		usrdata = data;

		if (strrchr(usrdata->str, '/') == NULL)
			return ENXIO; /* not a valid path */

		namei_simple_kernel(usrdata->str, NSM_FOLLOW_NOEMULROOT, &v);

		VOP_LOCK(v, LK_SHARED);
		if ((err = VOP_OPEN(v, FREAD, cred)) != 0)
			return err;
		if ((err = VOP_READ(v, &script, IO_NODELOCKED|IO_NORMAL, cred)) != 0)
			return err;
		if (script.uio_iov->iov_len == 0)
			return ENODATA;
		if (((char *)script.uio_iov->iov_base)[0] == 0x1b && !bytecode_on) {
			aprint_error_dev(sc_self, "loading bytecode is not enabled");
			return EINVAL;
		}
		VOP_UNLOCK(v);

		if ((L = findstate(usrdata->state)) == NULL)
			return EINVAL;
		sw = luaK_getenv(L, struct klua_Wrapper);

		mutex_enter(&sw->mtx);
		luaL_buffinit(L, &b);
		fillbuffer(&b, &script);
		luaL_pushresult(&b);
		if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK) {
			aprint_error("%s", lua_tostring(L, -1));
			mutex_exit(&sw->mtx);
			return EINVAL;
		}
		mutex_exit(&sw->mtx);

		break;
	}
	return 0;
}

/*
** 'require' in kernel
*/

static void
load_luakmod(lua_State *L)
{
	if (L == NULL)
		return;

	mutex_enter(drivermtx);
	__load_luakmod(L);
	mutex_exit(drivermtx);
}

static int
__load_luakmod(lua_State *L)
{
	const char *name = luaL_checkstring(L, 1);

	if (!check_kmod(name))
		if (module_autoload(name, MODULE_CLASS_MISC)) {
			lua_pop(drvL, 1);
			lua_pushfstring(L, "no lua in kernel module %s", name);
			return 0;
		}
	else
		goto out; /* module is already cached */

	if (!check_kmod(name)) { /* check if module registered itself to the driver */
		lua_pop(drvL, 1);
		lua_pushfstring(L, "lua in kernel module %s failed unexpectedly",
				name);
		return 0;
	}

out:
	lua_pushcfunction(L, lua_tocfunction(drvL, -1));
	lua_pop(drvL, 1);
	return 1;
}

typedef struct {
	size_t size;
} __packed alloc_header_t;

void *
lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
	void *nptr = NULL;

	const size_t hdr_size = sizeof(alloc_header_t);
	alloc_header_t *hdr = (alloc_header_t *) ((char *) ptr - hdr_size);

	if (nsize == 0) { /* freeing */
		if (ptr != NULL)
			kmem_intr_free(hdr, hdr->size);
	} else if (ptr != NULL && nsize <= hdr->size - hdr_size) /* shrinking */
		return ptr; /* don't need to reallocate */
	else { /* creating or expanding */
		km_flag_t sleep = cpu_intr_p() || cpu_softintr_p() ?
			KM_NOSLEEP : KM_SLEEP;

		size_t alloc_size = nsize + hdr_size;
		alloc_header_t *nhdr = kmem_intr_alloc(alloc_size, sleep);
		if (nhdr == NULL) /* failed to allocate */
			return NULL;

		nhdr->size = alloc_size;
		nptr = (void *) ((char *) nhdr + hdr_size);

		if (ptr != NULL) { /* expanding */
			memcpy(nptr, ptr, osize);
			kmem_intr_free(hdr, hdr->size);
		}
	}
	return nptr;
}

/*
** Kernel lua libraries must use these functions to
** register/unregister themselves to the driver
*/

static int
check_kmod(const char *name)
{
	lua_getfield(drvL, LUA_REGISTRYINDEX, "kmod_cache");
	lua_pushstring(drvL, name);
	lua_gettable(drvL, -1);
	return lua_isfunction(drvL, -1);
}

int
klua_mod_register(const char *name, lua_CFunction open)
{
	mutex_enter(&drivermtx);
	if (check_kmod(name)) {
		lua_pop(drvL, 1);
		aprint_error_dev(sc_self, "module already registered");
		return EINVAL;
	}

	lua_pop(drvL, 1);
	lua_getfield(drvL, LUA_REGISTRYINDEX, "kmod_cache");
	lua_pushcfunction(drvL, open);
	lua_setfield(drvL, -2, name);
	lua_pop(drvL, 1);
	mutex_exit(&drivermtx);
	return 0;
}

int
klua_mod_unregister(const char *name)
{
	mutex_enter(&drivermtx);
	if (!check_kmod(name)) {
		lua_pop(drvL, 1);
		aprint_error_dev(sc_self, "module doesn't exist");
		return EINVAL;
	}

	lua_pop(drvL, 1);
	lua_getfield(drvL, LUA_REGISTRYINDEX, "kmod_cache");
	lua_pushnil(drvL);
	lua_setfield(drvL, -2, name);
	lua_pop(drvL, 1);
	mutex_exit(&drivermtx);
	return 0;
}

int
klua_state_register(const char *name)
{
	if (name == NULL)
		return 1;

	mutex_enter(&drivermtx);
	lua_getfield(drvL, LUA_REGISTRYINDEX, "states");
	lua_pushlightuserdata(drvL, NULL);
	lua_setfield(drvL, -2, name);
	lua_pop(drvL, 1);
	mutex_exit(&drivermtx);
	return 0;
}

int
klua_state_unregister(const char *name)
{
	if (name == NULL)
		return 1;

	mutex_enter(&drivermtx);
	lua_getfield(drvL, LUA_REGISTRYINDEX, "states");
	lua_pushnil(drvL);
	lua_setfield(drvL, -2, name);
	lua_pop(drvL, 1);
	mutex_exit(&drivermtx);
	return 0;
}

/*
** These functions are part of the C API.
*/

inline lua_State *
luaL_newstate(void)
{
	lua_State *L = lua_newstate(lua_alloc, NULL);
	if (L) { /* expose the kernel require loader to lua */
		lua_pushcfunction(L, load_luakmod);
		lua_setfield(L, LUA_REGISTRYINDEX, "kmod_loader");
	}
	return L;
}

/*
** Kernel module specific attributes and functions
*/

MODULE(MODULE_CLASS_MISC, lua, NULL);

#ifdef _MODULE
static const struct cfiattrdata luabus_iattrdata = {
	"luabus", 0, { { NULL, NULL, 0 },}
};

static const struct cfiattrdata *const lua_attrs[] = {
	&luabus_iattrdata, NULL
};

CFDRIVER_DECL(lua, DV_DULL, lua_attrs);
extern struct cfattach lua_ca;
static int lualoc[] = {
	-1,
	-1,
	-1
};

static struct cfdata lua_cfdata[] = {
	{
		.cf_name = "lua",
		.cf_atname = "lua",
		.cf_unit = 0,
		.cf_fstate = FSTATE_STAR,
		.cf_loc = lualoc,
		.cf_flags = 0,
		.cf_pspec = NULL,
	},
	{ NULL, NULL, 0, FSTATE_NOTFOUND, NULL, 0, NULL }
};
#endif

static int
lua_modcmd(modcmd_t cmd, void *opaque)
{
#ifdef _MODULE
	devmajor_t cmajor, bmajor;
	int error = 0;
	drvL = lua_newstate(lua_alloc, NULL);
	cmajor = bmajor = NODEVMAJOR;

	if (drvL == NULL)
		return ENOMEM;

	lua_createtable(drvL, 0, 5);
	lua_setfield(drvL, LUA_REGISTRYINDEX, "kmod_cache");
	lua_createtable(drvL, 0, 5);
	lua_pushinteger(drvL, 0);
	lua_setfield(drvL, -2, "size");
	lua_setfield(drvL, LUA_REGISTRYINDEX, "states");
	mutex_init(&drivermtx, MUTEX_DEFAULT, IPL_NONE);
#endif
	switch (cmd) {
	case MODULE_CMD_INIT:
#ifdef _MODULE
		error = config_cfdriver_attach(&lua_cd);
		if (error)
			return error;

		error = config_cfattach_attach(lua_cd.cd_name,
		    &lua_ca);
		if (error) {
			config_cfdriver_detach(&lua_cd);
			aprint_error("%s: unable to register cfattach\n",
			    lua_cd.cd_name);
			return error;
		}
		error = config_cfdata_attach(lua_cfdata, 1);
		if (error) {
			config_cfattach_detach(lua_cd.cd_name,
			    &lua_ca);
			config_cfdriver_detach(&lua_cd);
			aprint_error("%s: unable to register cfdata\n",
			    lua_cd.cd_name);
			return error;
		}
		error = devsw_attach(lua_cd.cd_name, NULL, &bmajor,
		    &lua_cdevsw, &cmajor);
		if (error) {
			aprint_error("%s: unable to register devsw\n",
			    lua_cd.cd_name);
			config_cfattach_detach(lua_cd.cd_name, &lua_ca);
			config_cfdriver_detach(&lua_cd);
			return error;
		}
		config_attach_pseudo(lua_cfdata);
#endif
		return 0;
	case MODULE_CMD_FINI:
#ifdef _MODULE
		error = config_cfdata_detach(lua_cfdata);
		if (error)
			return error;

		config_cfattach_detach(lua_cd.cd_name, &lua_ca);
		config_cfdriver_detach(&lua_cd);
		devsw_detach(NULL, &lua_cdevsw);
#endif
		return 0;
	case MODULE_CMD_AUTOUNLOAD:
		/* no auto-unload */
		return EBUSY;
	default:
		return ENOTTY;
	}
}

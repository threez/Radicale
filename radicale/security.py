import os
import pwd
import grp
import sys
import resource
import ctypes
import ctypes.util
from .. import config, log

LIBC = ctypes.CDLL(ctypes.util.find_library("c"))

# disallow swapping (might contain secrets)
def disallow_swapping():
	return LIBC.mlockall(2)

# Disallow core dumps because they might contain secrets
def disallow_core_dumps():
	resource.setrlimit(resource.RLIMIT_CORE, [0, 0])

def drop_privileges(uid=None, gid=None):
	if os.getuid() != 0:  # Not root
		return False
	try:
		# Remove group privileges
		os.setgroups([])
		# Try setting the new uid/gid
		if uid and uid != "":
			os.setuid(pwd.getpwnam(uid).pw_uid)
		if gid and gid != "":
			os.setgid(grp.getgrnam(gid).gr_gid)
		return True
	except OSError:
		return False

def secure_server():
	disallow_core_dumps()
	disallow_swapping()
	uid = config.get("server", "setuid")
	gid = config.get("server", "setgid")
	if uid or gid:
		dropped = util.drop_privileges(uid, gid)
		if dropped:
			log.LOGGER.info("Privileges dropped")
		else:
			log.LOGGER.warn("Privileges NOT dropped")
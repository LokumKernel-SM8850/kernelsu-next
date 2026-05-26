#ifndef __KSU_H_SETUID_HOOK
#define __KSU_H_SETUID_HOOK

#include <linux/types.h>

void ksu_setuid_hook_init(void);
void ksu_setuid_hook_exit(void);
int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid);

#endif

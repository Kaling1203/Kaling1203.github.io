---
layout: post
title: ELF 加载过程
subtitle: 
categories: markdown
tags: [ELF]
---

# ELF 文件执行过程

用户空间程序调用 `execv` 系的系统调用， 来触发执行。以一个简单的程序为例：

```c
#include <stdio.h>

int main(int argc, char*argv[])
{
    return 0;
}
```

用 `strace` 抓取它的执行过程：

```bash
$ strace ./hello
execve("./hello", ["./hello"], 0x7fffa3fa0630 /* 71 vars */) = 0
brk(NULL)                               = 0x55f8604f5000
arch_prctl(0x3001 /* ARCH_??? */, 0x7ffd17e421f0) = -1 EINVAL (Invalid argument)
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/cuda-11.3/lib64/tls/haswell/x86_64/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat("/usr/local/cuda-11.3/lib64/tls/haswell/x86_64", 0x7ffd17e41440) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/cuda-11.3/lib64/tls/haswell/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat("/usr/local/cuda-11.3/lib64/tls/haswell", 0x7ffd17e41440) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/cuda-11.3/lib64/tls/x86_64/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat("/usr/local/cuda-11.3/lib64/tls/x86_64", 0x7ffd17e41440) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/cuda-11.3/lib64/tls/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat("/usr/local/cuda-11.3/lib64/tls", 0x7ffd17e41440) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/cuda-11.3/lib64/haswell/x86_64/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat("/usr/local/cuda-11.3/lib64/haswell/x86_64", 0x7ffd17e41440) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/cuda-11.3/lib64/haswell/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat("/usr/local/cuda-11.3/lib64/haswell", 0x7ffd17e41440) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/cuda-11.3/lib64/x86_64/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat("/usr/local/cuda-11.3/lib64/x86_64", 0x7ffd17e41440) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/usr/local/cuda-11.3/lib64/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
stat("/usr/local/cuda-11.3/lib64", {st_mode=S_IFDIR|0755, st_size=4096, ...}) = 0
openat(AT_FDCWD, "tls/haswell/x86_64/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "tls/haswell/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "tls/x86_64/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "tls/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "haswell/x86_64/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "haswell/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "x86_64/libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "libc.so.6", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
fstat(3, {st_mode=S_IFREG|0644, st_size=106088, ...}) = 0
mmap(NULL, 106088, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f88943ec000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\360q\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\t\233\222%\274\260\320\31\331\326\10\204\276X>\263"..., 68, 880) = 68
fstat(3, {st_mode=S_IFREG|0755, st_size=2029224, ...}) = 0
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7f88943ea000
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
pread64(3, "\4\0\0\0\20\0\0\0\5\0\0\0GNU\0\2\0\0\300\4\0\0\0\3\0\0\0\0\0\0\0", 32, 848) = 32
pread64(3, "\4\0\0\0\24\0\0\0\3\0\0\0GNU\0\t\233\222%\274\260\320\31\331\326\10\204\276X>\263"..., 68, 880) = 68
mmap(NULL, 2036952, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7f88941f8000
mprotect(0x7f889421d000, 1847296, PROT_NONE) = 0
mmap(0x7f889421d000, 1540096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x25000) = 0x7f889421d000
mmap(0x7f8894395000, 303104, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19d000) = 0x7f8894395000
mmap(0x7f88943e0000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1e7000) = 0x7f88943e0000
mmap(0x7f88943e6000, 13528, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7f88943e6000
close(3)                                = 0
arch_prctl(ARCH_SET_FS, 0x7f88943eb540) = 0
mprotect(0x7f88943e0000, 12288, PROT_READ) = 0
mprotect(0x55f85f235000, 4096, PROT_READ) = 0
mprotect(0x7f8894433000, 4096, PROT_READ) = 0
munmap(0x7f88943ec000, 106088)          = 0
exit_group(0)                           = ?
+++ exited with 0 +++
```

可以看到通过系统调用 `execve` 触发执行， 看下 `Linux` 中对应的实现：

> <font color="red">注意， evecve 成功执行后， 不会返回调用方</font>

```c
SYSCALL_DEFINE3(execve,
                const char __user *, filename,
                const char __user *const __user *, argv,
                const char __user *const __user *, envp)
{
        return do_execve(getname(filename), argv, envp);
}

static int do_execve(struct filename *filename,
        const char __user *const __user *__argv,
        const char __user *const __user *__envp)
{
        struct user_arg_ptr argv = { .ptr.native = __argv };
        struct user_arg_ptr envp = { .ptr.native = __envp };
        return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}
```

使用 `filename` 和 `user_arg_ptr` 保存参数

```c
struct filename {
        const char              *name;  /* pointer to actual string */
        const __user char       *uptr;  /* original userland pointer */
        int                     refcnt;
        struct audit_names      *aname;
        const char              iname[];
};

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
        bool is_compat;
#endif
        union {
                const char __user *const __user *native;
#ifdef CONFIG_COMPAT
                const compat_uptr_t __user *compat;
#endif
        } ptr;
};
```

然后执行 `do_execveat_common()`， 在继续之前， 注意它的第一个参数， 表明使用当前工作目录：

```c
#define AT_FDCWD                -100    /* Special value used to indicate                                                                                                                                  
                                           openat should use the current                                                                                                                                   
                                           working directory. */
```

继续看 `do_execveat_common()` 的实现：

```c
static int do_execveat_common(int fd, struct filename *filename,
                              struct user_arg_ptr argv,
                              struct user_arg_ptr envp,
                              int flags)
{
        struct linux_binprm *bprm;
        int retval;

        if (IS_ERR(filename))
                return PTR_ERR(filename);

        /*                                                                                                                                                                                                 
         * We move the actual failure in case of RLIMIT_NPROC excess from                                                                                                                                  
         * set*uid() to execve() because too many poorly written programs                                                                                                                                  
         * don't check setuid() return code.  Here we additionally recheck                                                                                                                                 
         * whether NPROC limit is still exceeded.                                                                                                                                                          
         */
        if ((current->flags & PF_NPROC_EXCEEDED) &&
            atomic_read(&current_user()->processes) > rlimit(RLIMIT_NPROC)) {
                retval = -EAGAIN;
                goto out_ret;
        }

        /* We're below the limit (still or again), so we don't want to make                                                                                                                                
         * further execve() calls fail. */
        current->flags &= ~PF_NPROC_EXCEEDED;

    	// 初始化 linux_binprm 结构体， 并分配栈地址
        bprm = alloc_bprm(fd, filename);
        if (IS_ERR(bprm)) {
                retval = PTR_ERR(bprm);
                goto out_ret;
        }

        retval = count(argv, MAX_ARG_STRINGS);
        if (retval < 0)
                goto out_free;
        bprm->argc = retval;

        retval = count(envp, MAX_ARG_STRINGS);
        if (retval < 0)
                goto out_free;
        bprm->envc = retval;

        retval = bprm_stack_limits(bprm);
        if (retval < 0)
                goto out_free;

    	// 把参数入栈： filename， env 和 argv
        retval = copy_string_kernel(bprm->filename, bprm);
        if (retval < 0)
                goto out_free;
        bprm->exec = bprm->p;

        retval = copy_strings(bprm->envc, envp, bprm);
        if (retval < 0)
                goto out_free;

        retval = copy_strings(bprm->argc, argv, bprm);
        if (retval < 0)
                goto out_free;

        retval = bprm_execve(bprm, fd, filename, flags);
out_free:
        free_bprm(bprm);

out_ret:
        putname(filename);
        return retval;
}
```

可以看到， 这个函数主要用传入的参数来初始化 `linux_binprm`， 然后通过 `bprm_execve()` 执行。`linux_binprm` 这个结构体使用来保存加载二进制文件所需的信息， 具体定义如下：

```c
/*                                                                                                                                                                                                         
 * This structure is used to hold the arguments that are used when loading binaries.                                                                                                                       
 */
struct linux_binprm {
#ifdef CONFIG_MMU
        struct vm_area_struct *vma;
        unsigned long vma_pages;
#else
# define MAX_ARG_PAGES  32
        struct page *page[MAX_ARG_PAGES];
#endif
        struct mm_struct *mm;
        unsigned long p; /* current top of mem */
        unsigned long argmin; /* rlimit marker for copy_strings() */
        unsigned int
                /* Should an execfd be passed to userspace? */
                have_execfd:1,

                /* Use the creds of a script (see binfmt_misc) */
                execfd_creds:1,
                /*                                                                                                                                                                                         
                 * Set by bprm_creds_for_exec hook to indicate a                                                                                                                                           
                 * privilege-gaining exec has happened. Used to set                                                                                                                                        
                 * AT_SECURE auxv for glibc.                                                                                                                                                               
                 */
                secureexec:1,
                /*                                                                                                                                                                                         
                 * Set when errors can no longer be returned to the                                                                                                                                        
                 * original userspace.                                                                                                                                                                     
                 */
                point_of_no_return:1;
#ifdef __alpha__
        unsigned int taso:1;
#endif
        struct file *executable; /* Executable to pass to the interpreter */
        struct file *interpreter;
        struct file *file;
        struct cred *cred;      /* new credentials */
        int unsafe;             /* how unsafe this exec is (mask of LSM_UNSAFE_*) */
        unsigned int per_clear; /* bits to clear in current->personality */
        int argc, envc;			// argv 数量 和 env 数量
        const char *filename;   /* Name of binary as seen by procps */
        const char *interp;     /* Name of the binary really executed. Most                                                                                                                                
                                   of the time same as filename, but could be                                                                                                                              
                                   different for binfmt_{misc,script} */
        const char *fdpath;     /* generated filename for execveat */
        unsigned interp_flags;
        int execfd;             /* File descriptor of the executable */
        unsigned long loader, exec;

        struct rlimit rlim_stack; /* Saved RLIMIT_STACK used during exec. */

        char buf[BINPRM_BUF_SIZE];
} __randomize_layout;
```

看下 `alloc_bprm()` 的实现先：

```c
static struct linux_binprm *alloc_bprm(int fd, struct filename *filename)
{
        struct linux_binprm *bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
        int retval = -ENOMEM;
        if (!bprm)
                goto out;

        if (fd == AT_FDCWD || filename->name[0] == '/') {
                bprm->filename = filename->name;
        } else {
                if (filename->name[0] == '\0')
                        bprm->fdpath = kasprintf(GFP_KERNEL, "/dev/fd/%d", fd);
                else
                        bprm->fdpath = kasprintf(GFP_KERNEL, "/dev/fd/%d/%s",
                                                  fd, filename->name);
                if (!bprm->fdpath)
                        goto out_free;

                bprm->filename = bprm->fdpath;
        }
        bprm->interp = bprm->filename;

        retval = bprm_mm_init(bprm);
        if (retval)
                goto out_free;
        return bprm;

out_free:
        free_bprm(bprm);
out:
        return ERR_PTR(retval);
}

/*                                                                                                                                                                                                         
 * Create a new mm_struct and populate it with a temporary stack                                                                                                                                           
 * vm_area_struct.  We don't have enough context at this point to set the stack                                                                                                                            
 * flags, permissions, and offset, so we use temporary values.  We'll update                                                                                                                               
 * them later in setup_arg_pages().                                                                                                                                                                        
 */
static int bprm_mm_init(struct linux_binprm *bprm)
{
        int err;
        struct mm_struct *mm = NULL;

        bprm->mm = mm = mm_alloc();
        err = -ENOMEM;
        if (!mm)
                goto err;

        /* Save current stack limit for all calculations made during exec. */
        task_lock(current->group_leader);
        bprm->rlim_stack = current->signal->rlim[RLIMIT_STACK];
        task_unlock(current->group_leader);

        err = __bprm_mm_init(bprm);
        if (err)
                goto err;

        return 0;

err:
        if (mm) {
                bprm->mm = NULL;
                mmdrop(mm);
        }

        return err;
}

static int __bprm_mm_init(struct linux_binprm *bprm)
{
        int err;
        struct vm_area_struct *vma = NULL;
        struct mm_struct *mm = bprm->mm;

        bprm->vma = vma = vm_area_alloc(mm);
        if (!vma)
                return -ENOMEM;
        vma_set_anonymous(vma);

        if (mmap_write_lock_killable(mm)) {
                err = -EINTR;
                goto err_free;
        }

        /*                                                                                                                                                                                                 
         * Place the stack at the largest stack address the architecture                                                                                                                                   
         * supports. Later, we'll move this to an appropriate place. We don't                                                                                                                              
         * use STACK_TOP because that can depend on attributes which aren't                                                                                                                                
         * configured yet.                                                                                                                                                                                 
         */
    	/* 准备栈区域 ？ */
        BUILD_BUG_ON(VM_STACK_FLAGS & VM_STACK_INCOMPLETE_SETUP);
        vma->vm_end = STACK_TOP_MAX;
        vma->vm_start = vma->vm_end - PAGE_SIZE;
        vma->vm_flags = VM_SOFTDIRTY | VM_STACK_FLAGS | VM_STACK_INCOMPLETE_SETUP;
        vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);

        err = insert_vm_struct(mm, vma);
        if (err)
                goto err;

        mm->stack_vm = mm->total_vm = 1;
        mmap_write_unlock(mm);
        bprm->p = vma->vm_end - sizeof(void *);		// 初始化 linux_binprm->p, 一个 page 大小
        return 0;
err:
        mmap_write_unlock(mm);
err_free:
        bprm->vma = NULL;
        vm_area_free(vma);
        return err;
}
```

继续看 `bprm_execve()` 函数：

```c
/*                                                                                                                                                                                                         
 * sys_execve() executes a new program.                                                                                                                                                                    
 */
static int bprm_execve(struct linux_binprm *bprm,
                       int fd, struct filename *filename, int flags)
{
        struct file *file;
        struct files_struct *displaced;
        int retval;

        /*                                                                                                                                                                                                 
         * Cancel any io_uring activity across execve                                                                                                                                                      
         */
        io_uring_task_cancel();

        retval = unshare_files(&displaced);
        if (retval)
                return retval;

        retval = prepare_bprm_creds(bprm);
        if (retval)
                goto out_files;

        check_unsafe_exec(bprm);
        current->in_execve = 1;

        file = do_open_execat(fd, filename, flags);	// 打开文件
        retval = PTR_ERR(file);
        if (IS_ERR(file))
                goto out_unmark;

        sched_exec();	// 负载均衡

        bprm->file = file;
        /*                                                                                                                                                                                                 
         * Record that a name derived from an O_CLOEXEC fd will be                                                                                                                                         
         * inaccessible after exec. Relies on having exclusive access to                                                                                                                                   
         * current->files (due to unshare_files above).                                                                                                                                                    
         */
        if (bprm->fdpath &&
            close_on_exec(fd, rcu_dereference_raw(current->files->fdt)))
                bprm->interp_flags |= BINPRM_FLAGS_PATH_INACCESSIBLE;

        /* Set the unchanging part of bprm->cred */
        retval = security_bprm_creds_for_exec(bprm);
        if (retval)
                goto out;

        retval = exec_binprm(bprm);	// 真正执行的部分
        if (retval < 0)
                goto out;

        /* execve succeeded */
        current->fs->in_exec = 0;
        current->in_execve = 0;
        rseq_execve(current);
        acct_update_integrals(current);
        task_numa_free(current, false);
        if (displaced)
                put_files_struct(displaced);
        return retval;

out:
        /*                                                                                                                                                                                                 
         * If past the point of no return ensure the the code never                                                                                                                                        
         * returns to the userspace process.  Use an existing fatal                                                                                                                                        
         * signal if present otherwise terminate the process with                                                                                                                                          
         * SIGSEGV.                                                                                                                                                                                        
         */
        if (bprm->point_of_no_return && !fatal_signal_pending(current))
                force_sigsegv(SIGSEGV);

out_unmark:
        current->fs->in_exec = 0;
        current->in_execve = 0;

out_files:
        if (displaced)
                reset_files_struct(displaced);

        return retval;
}
```

看下执行部分 `exec_binprm()`：

```c
static int exec_binprm(struct linux_binprm *bprm)
{
        pid_t old_pid, old_vpid;
        int ret, depth;

        /* Need to fetch pid before load_binary changes it */
        old_pid = current->pid;
        rcu_read_lock();
        old_vpid = task_pid_nr_ns(current, task_active_pid_ns(current->parent));
        rcu_read_unlock();

        /* This allows 4 levels of binfmt rewrites before failing hard. */
        for (depth = 0;; depth++) {
                struct file *exec;
                if (depth > 5)
                        return -ELOOP;

                ret = search_binary_handler(bprm);
                if (ret < 0)
                        return ret;
                if (!bprm->interpreter)
                        break;

                exec = bprm->file;
                bprm->file = bprm->interpreter;
                bprm->interpreter = NULL;

                allow_write_access(exec);
                if (unlikely(bprm->have_execfd)) {
                        if (bprm->executable) {
                                fput(exec);
                                return -ENOEXEC;
                        }
                        bprm->executable = exec;
                } else
                        fput(exec);
        }

        audit_bprm(bprm);
        trace_sched_process_exec(current, old_pid, bprm);
        ptrace_event(PTRACE_EVENT_EXEC, old_vpid);
        proc_exec_connector(current);
        return 0;
}
```

通过 `search_binary_handler()` 查找对应的处理模块并执行：

```c
/*                                                                                                                                                                                                         
 * cycle the list of binary formats handler, until one recognizes the image                                                                                                                                
 */
static int search_binary_handler(struct linux_binprm *bprm)
{
        bool need_retry = IS_ENABLED(CONFIG_MODULES);
        struct linux_binfmt *fmt;
        int retval;

        retval = prepare_binprm(bprm);
        if (retval < 0)
                return retval;

        retval = security_bprm_check(bprm);
        if (retval)
                return retval;

        retval = -ENOENT;
 retry:
        read_lock(&binfmt_lock);
        list_for_each_entry(fmt, &formats, lh) {
                if (!try_module_get(fmt->module))
                        continue;
                read_unlock(&binfmt_lock);

                retval = fmt->load_binary(bprm);		// 调用 linux_binfmt->load_binary() 加载

                read_lock(&binfmt_lock);
                put_binfmt(fmt);
                if (bprm->point_of_no_return || (retval != -ENOEXEC)) {
                        read_unlock(&binfmt_lock);
                        return retval;
                }
        }
        read_unlock(&binfmt_lock);

        if (need_retry) {
                if (printable(bprm->buf[0]) && printable(bprm->buf[1]) &&
                    printable(bprm->buf[2]) && printable(bprm->buf[3]))
                        return retval;
                if (request_module("binfmt-%04x", *(ushort *)(bprm->buf + 2)) < 0)
                        return retval;
                need_retry = false;
                goto retry;
        }

        return retval;
}
```

先看 `prepare_binprm()` 的实现：

```c
/* sizeof(linux_binprm->buf) */
#define BINPRM_BUF_SIZE 256

/*                                                                                                                                                                                                         
 * Fill the binprm structure from the inode.                                                                                                                                                               
 * Read the first BINPRM_BUF_SIZE bytes                                                                                                                                                                    
 *                                                                                                                                                                                                         
 * This may be called multiple times for binary chains (scripts for example).                                                                                                                              
 */
static int prepare_binprm(struct linux_binprm *bprm)
{
 	loff_t pos = 0;

	memset(bprm->buf, 0, BINPRM_BUF_SIZE);
	return kernel_read(bprm->file, bprm->buf, BINPRM_BUF_SIZE, &pos);
}

```

读取 256 个字节， 保存到 `linux_binprm->buf` 中， 然后通过 `linux_binfmt->load_binary()` 尝试加载

这里涉及到一个 `linux_binfmt`

```c
/*                                                                                                                                                                                                         
 * This structure defines the functions that are used to load the binary formats that                                                                                                                      
 * linux accepts.                                                                                                                                                                                          
 */
struct linux_binfmt {
        struct list_head lh;
        struct module *module;
        int (*load_binary)(struct linux_binprm *);
        int (*load_shlib)(struct file *);
        int (*core_dump)(struct coredump_params *cprm);
        unsigned long min_coredump;     /* minimal dump size */
} __randomize_layout;
```

其他模块通过 `register_binfmt()` 将自己注册到 `formats` 链表上， 这样 `linux` 就可以支援对应格式文件的执行

```c
static LIST_HEAD(formats);
static DEFINE_RWLOCK(binfmt_lock);

void __register_binfmt(struct linux_binfmt * fmt, int insert)
{
        BUG_ON(!fmt);
        if (WARN_ON(!fmt->load_binary))
                return;
        write_lock(&binfmt_lock);
        insert ? list_add(&fmt->lh, &formats) :
                 list_add_tail(&fmt->lh, &formats);
        write_unlock(&binfmt_lock);
}

EXPORT_SYMBOL(__register_binfmt);

void unregister_binfmt(struct linux_binfmt * fmt)
{
        write_lock(&binfmt_lock);
        list_del(&fmt->lh);
        write_unlock(&binfmt_lock);
}

/* Registration of default binfmt handlers */
static inline void register_binfmt(struct linux_binfmt *fmt)
{
        __register_binfmt(fmt, 0);
}
/* Same as above, but adds a new binfmt at the top of the list */
static inline void insert_binfmt(struct linux_binfmt *fmt)
{
        __register_binfmt(fmt, 1);
}
```

看下 ELF 对应的定义：

```c
static struct linux_binfmt elf_format = {
        .module         = THIS_MODULE,
        .load_binary    = load_elf_binary,
        .load_shlib     = load_elf_library,
        .core_dump      = elf_core_dump,
        .min_coredump   = ELF_EXEC_PAGESIZE,
};
```

对应的 实现为 `load_elf_binary()`

```c
static int load_elf_binary(struct linux_binprm *bprm)
{
}
```

代码太长， 就补贴了， 大体流程如下：

1. 检查 ELF 文件的 elf header， 判断是否有异常， 有异常就退出执行， 否则继续

2. 根据 elf header 的信息读出 ELF 文件的 program header， 解析 PT_GNU_PROPERTY & PT_INTERP 这两个 entry

   Linux 中有使用的 program header type 如下：

   ```c
   /* These constants are for the segment types stored in the image headers */
   #define PT_NULL    0
   #define PT_LOAD    1
   #define PT_DYNAMIC 2
   #define PT_INTERP  3
   #define PT_NOTE    4
   #define PT_SHLIB   5
   #define PT_PHDR    6
   #define PT_TLS     7               /* Thread local storage segment */
   #define PT_LOOS    0x60000000      /* OS-specific */
   #define PT_HIOS    0x6fffffff      /* OS-specific */
   #define PT_LOPROC  0x70000000
   #define PT_HIPROC  0x7fffffff
   #define PT_GNU_EH_FRAME         0x6474e550
   #define PT_GNU_PROPERTY         0x6474e553
   
   #define PT_GNU_STACK    (PT_LOOS + 0x474e551)
   ```

3. 根据 PT_INTERP entry 中的 interpreter 信息， 找到 interpreter 的路径， 并加载 interpreter 的 elf header

4. 解析 ELF 文件 PT_GNU_STACK entry 中的信息， 判断 stack 的权限， 可选的权限如下：

   ```c
   /* Stack area protections */
   #define EXSTACK_DEFAULT   0     /* Whatever the arch defaults to */
   #define EXSTACK_DISABLE_X 1     /* Disable executable stacks */
   #define EXSTACK_ENABLE_X  2     /* Enable executable stacks */
   ```

5. 检查 interpreter 的 elf header， 判断是否存在异常， 没有异常就读取 interpreter 的 program header

6. 调用 `begin_new_exec()`切换 内存地址空间， 关闭之前进程打开的文件列表，

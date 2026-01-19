#ifndef _PROCESS_H
#define _PROCESS_H

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/namei.h>

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,14,83))
#include <linux/sched/mm.h>
#endif

#define ARC_PATH_MAX 256

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
static size_t get_module_base(pid_t pid, char* name)
{
\tstruct task_struct* task;
\tstruct mm_struct* mm;
\tstruct vm_area_struct *vma;
\tsize_t count = 0;
\tchar buf[ARC_PATH_MAX];
\tchar *path_nm = NULL;

\trcu_read_lock();
\ttask = pid_task(find_vpid(pid), PIDTYPE_PID);
\tif (!task) {
\t\trcu_read_unlock();
\t\treturn 0;
\t}
\trcu_read_unlock();

\tmm = get_task_mm(task);
\tif (!mm) {
\t\treturn 0;
\t}
    // В новых ядрах итерация VMA может отличаться, здесь оставлена ваша логика
\tvma = find_vma(mm, 0);
\twhile (vma) {
\t\tif (vma->vm_file) {
\t\t\tpath_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX-1);
\t\t\tif (!IS_ERR(path_nm) && !strcmp(kbasename(path_nm), name)) {
\t\t\t\tcount = (uintptr_t)vma->vm_start;
\t\t\t\tbreak;
\t\t\t}
\t\t}
\t\tif (vma->vm_end >= ULONG_MAX) break; 
\t\tvma = find_vma(mm, vma->vm_end);
\t}
\tmmput(mm);
\treturn count;
}
#else
uintptr_t get_module_base(pid_t pid, const char *name)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    size_t count = 0;
    char buf[ARC_PATH_MAX];
    char *path_nm = "";
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    rcu_read_unlock();

    if (!task) return 0;

    mm = get_task_mm(task);
    if (!mm) return 0;

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
            struct file *file = vma->vm_file;
            if (file) {
                path_nm = d_path(&file->f_path, buf, ARC_PATH_MAX-1);
                if (!strcmp(kbasename(path_nm), name)) {
                    count = vma->vm_start;
                    break;
                }
            }
    }

    mmput(mm);
    return count;
}
#endif

#endif

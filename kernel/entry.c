#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "comm.h"
#include "memory.h"
#include "process.h"

static dev_t mem_tool_dev_t;
static struct {
    struct cdev cdev;
} memdev;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0))
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

static int dispatch_open(struct inode *node, struct file *file) {
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file) {
    return 0;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name_buf[0x100];
    int ret = 0;
    
    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) 
                return -EFAULT;
            ret = read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EFAULT;
            break;
            
        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) 
                return -EFAULT;
            ret = write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EFAULT;
            break;
            
        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb))) 
                return -EFAULT;
            if (copy_from_user(name_buf, (void __user*)mb.name, sizeof(name_buf)-1)) 
                return -EFAULT;
            name_buf[sizeof(name_buf)-1] = '';
            
            mb.base = get_module_base(mb.pid, name_buf);
            
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb))) 
                return -EFAULT;
            break;
            
        default:
            ret = -EINVAL;
            break;
    }
    
    return (long)ret;
}

static struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

static int __init driver_entry(void) {
    int ret;
    
    // Регистрация устройства (без имени для stealth)
    ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, "");
    if (ret < 0) return ret;
    
    cdev_init(&memdev.cdev, &dispatch_functions);
    memdev.cdev.owner = THIS_MODULE;
    
    ret = cdev_add(&memdev.cdev, mem_tool_dev_t, 1);
    if (ret < 0) {
        unregister_chrdev_region(mem_tool_dev_t, 1);
        return ret;
    }
    
    // DKOM - полное сокрытие модуля
    list_del_init(&THIS_MODULE->list);
    list_del_init(&THIS_MODULE->source_list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    memset(THIS_MODULE->name, 0, MODULE_NAME_LEN);
    
    return 0;
}

static void __exit driver_unload(void) {
    list_add_tail_rcu(&THIS_MODULE->list, THIS_MODULE->list.prev);
    cdev_del(&memdev.cdev);
    unregister_chrdev_region(mem_tool_dev_t, 1);
}

module_init(driver_entry);
module_exit(driver_unload);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anonymous");

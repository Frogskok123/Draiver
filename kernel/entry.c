#include <linux/module.h>
#include <linux/tty.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/cdev.h>

#include "comm.h"
#include "memory.h"
#include "process.h"
#include "hide_process.h" // Оставляем
#include "breakpoint.h"   // Оставляем

static dev_t mem_tool_dev_t;
static struct {
    struct cdev cdev;
} memdev;

// Обработчики открытия и закрытия (теперь пустые)
static int dispatch_open(struct inode *node, struct file *file) {
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file) {
    return 0;
}

// Основной диспетчер IOCTL
long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg) {
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char name_buf[0x100];
    int ret = 0;

    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) return -EFAULT;
            ret = read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EFAULT;
            break;

        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm))) return -EFAULT;
            ret = write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EFAULT;
            break;

        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb))) return -EFAULT;
            if (copy_from_user(name_buf, (void __user*)mb.name, sizeof(name_buf)-1)) return -EFAULT;
            name_buf[sizeof(name_buf)-1] = '';
            mb.base = get_module_base(mb.pid, name_buf);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb))) return -EFAULT;
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
    .compat_ioctl = dispatch_ioctl, // Добавлено для совместимости
};

static int __init driver_entry(void) {
    int ret;
    
    // Регистрация устройства
    // Имя "jiangnight" можно изменить, если нужно скрыть присутствие в /dev
    ret = alloc_chrdev_region(&mem_tool_dev_t, 0, 1, "jiangnight");
    if (ret < 0) return ret;
    
    cdev_init(&memdev.cdev, &dispatch_functions);
    memdev.cdev.owner = THIS_MODULE;
    ret = cdev_add(&memdev.cdev, mem_tool_dev_t, 1);
    if (ret < 0) {
        unregister_chrdev_region(mem_tool_dev_t, 1);
        return ret;
    }
    
    // Код сокрытия модуля (list_del) удален по запросу
    
    return 0;
}

static void __exit driver_unload(void) {
    cdev_del(&memdev.cdev);
    unregister_chrdev_region(mem_tool_dev_t, 1);
}

module_init(driver_entry);
module_exit(driver_unload);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oneplus");

#ifndef _MEMORY_H
#define _MEMORY_H

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <linux/sched/mm.h>
#include <linux/pid.h>
#include <linux/version.h>
#include <asm/pgtable.h>
#include <linux/highmem.h>
#include <linux/slab.h>
// ==========================================
// ТРАНСЛЯЦИЯ (VIRT TO PHYS)
// ==========================================
static struct page* translate_to_page(struct mm_struct* mm, uintptr_t va) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    
    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;
    
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;
    
    pud = pud_offset(p4d, va);
    if(pud_none(*pud) || pud_bad(*pud)) return NULL;
    
    pmd = pmd_offset(pud, va);
    if(pmd_none(*pmd)) return NULL;
    
    pte = pte_offset_kernel(pmd, va);
    if(!pte || pte_none(*pte) || !pte_present(*pte)) return NULL;
    
    // Защита от kernel panic
    if (pte_special(*pte)) return NULL;
    
#ifdef pte_devmap
    if (pte_devmap(*pte)) return NULL;
#endif
    
    return pte_page(*pte);
}

// ==========================================
// БЫСТРОЕ ЧТЕНИЕ (KMAP)
// ==========================================
static size_t read_page_kmap(struct page* page, uintptr_t addr, void* buffer, size_t size) {
    void *map_ptr;
    unsigned long offset = addr & (PAGE_SIZE - 1);
    char kbuf_stack[128];
    char *kbuf = kbuf_stack;
    bool allocated = false;
    
    if (size > sizeof(kbuf_stack)) {
        kbuf = kmalloc(size, GFP_ATOMIC);
        if (!kbuf) return 0;
        allocated = true;
    }
    
    map_ptr = kmap_atomic(page);
    if (!map_ptr) {
        if (allocated) kfree(kbuf);
        return 0;
    }
    
    memcpy(kbuf, (char*)map_ptr + offset, size);
    kunmap_atomic(map_ptr);
    
    if (copy_to_user(buffer, kbuf, size)) {
        if (allocated) kfree(kbuf);
        return 0;
    }
    
    if (allocated) kfree(kbuf);
    return size;
}

// ==========================================
// БЫСТРАЯ ЗАПИСЬ (KMAP)
// ==========================================
static size_t write_page_kmap(struct page* page, uintptr_t addr, void* buffer, size_t size) {
    void *map_ptr;
    unsigned long offset = addr & (PAGE_SIZE - 1);
    char kbuf_stack[128];
    char *kbuf = kbuf_stack;
    bool allocated = false;
    
    if (size > sizeof(kbuf_stack)) {
        kbuf = kmalloc(size, GFP_ATOMIC);
        if (!kbuf) return 0;
        allocated = true;
    }
    
    if (copy_from_user(kbuf, buffer, size)) {
        if (allocated) kfree(kbuf);
        return 0;
    }
    
    map_ptr = kmap_atomic(page);
    if (!map_ptr) {
        if (allocated) kfree(kbuf);
        return 0;
    }
    
    memcpy((char*)map_ptr + offset, kbuf, size);
    kunmap_atomic(map_ptr);
    
    if (allocated) kfree(kbuf);
    return size;
}

// ==========================================
// ГЛАВНЫЙ ЦИКЛ (С БЛОКИРОВКОЙ)
// ==========================================
bool read_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    struct page* page;
    size_t chunk_size;
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    
    if (!task) return false;
    
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return false;
    }
    
    if (mmap_read_lock_killable(mm)) {
        mmput(mm);
        put_task_struct(task);
        return false;
    }
    
    while (size > 0) {
        chunk_size = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));
        
        page = translate_to_page(mm, addr);
        if (page) {
            if (!read_page_kmap(page, addr, buffer, chunk_size)) {
                if (clear_user(buffer, chunk_size)) { }
            }
        } else {
            if (clear_user(buffer, chunk_size)) { }
        }
        
        size -= chunk_size;
        buffer = (char*)buffer + chunk_size;
        addr += chunk_size;
    }
    
    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    return true;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void* buffer, size_t size) {
    struct task_struct* task;
    struct mm_struct* mm;
    struct page* page;
    size_t chunk_size;
    
    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) get_task_struct(task);
    rcu_read_unlock();
    
    if (!task) return false;
    
    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return false;
    }
    
    if (mmap_read_lock_killable(mm)) {
        mmput(mm);
        put_task_struct(task);
        return false;
    }
    
    while (size > 0) {
        chunk_size = min(PAGE_SIZE - (addr & (PAGE_SIZE - 1)), min(size, PAGE_SIZE));
        
        page = translate_to_page(mm, addr);
        if (page) {
            write_page_kmap(page, addr, buffer, chunk_size);
        }
        
        size -= chunk_size;
        buffer = (char*)buffer + chunk_size;
        addr += chunk_size;
    }
    
    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    return true;
}

#endif

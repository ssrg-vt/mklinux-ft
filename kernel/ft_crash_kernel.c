/*
 * ft_crash_kernel.c
 *
 * Author: Marina
 */


#include <linux/kernel.h>
#include <linux/ft_replication.h>
#include <linux/sched.h>
#include <linux/pcn_kmsg.h>
#include <linux/pci.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/if.h>
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/mm.h>

struct crash_kernel_notification_msg{
        struct pcn_kmsg_hdr header;
	resource_size_t dmesg_buf_phys_addr;
	int dmesg_size;
	unsigned long dmesg_pfn;
};

struct workqueue_struct *crash_wq;

extern int _cpu;
extern int pci_dev_list_remove(int compatible, char *vendor, char *model,
               char* slot, char *strflags, int flags);

struct dentry  *file1;
resource_size_t primary_dmesg_buf_phys_addr;
int primary_dmesg_size;
unsigned long primary_dmesg_pfn;

struct mmap_info {
	char *data;	/* the data */
	int reference;       /* how many times it is mmapped */  	
};


/* keep track of how many times it is mmapped */

void mmap_open(struct vm_area_struct *vma)
{
	struct mmap_info *info = (struct mmap_info *)vma->vm_private_data;
	if(!info){
		printk("%s WARINIG no mmap_info\n", __func__);
		return;
	}
	info->reference++;
	printk("%s reference %d\n", __func__,info->reference );
}

void mmap_close(struct vm_area_struct *vma)
{
	struct mmap_info *info = (struct mmap_info *)vma->vm_private_data;
	if(!info){
                printk("%s WARINIG no mmap_info\n", __func__);
                return;
        }

	info->reference--;
	printk("%s reference %d\n", __func__,info->reference );
}

/* nopage is called the first time a memory area is accessed which is not in memory,
 * it does the actual mapping between kernel and user space memory
 */
struct page *mmap_nopage(struct vm_area_struct *vma, unsigned long address, int *type)
{
	struct page *page;
	struct mmap_info *info;
	/* is the address valid? */
	if (address > vma->vm_end) {
		printk("invalid address\n");
		return NULL;
	}
	/* the data is in vma->vm_private_data */
	info = (struct mmap_info *)vma->vm_private_data;
	if (!info->data) {
		printk("no data\n");
		return NULL;	
	}

	/* get the page */
	page = virt_to_page(info->data);
	
	/* increment the reference count of this page */
	get_page(page);
	/* type is the page fault type */
	if (type)
		*type = VM_FAULT_MINOR;

	return page;
}

int mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf){
	unsigned long address= (unsigned long)vmf->virtual_address;
	struct page *page;	
	struct mmap_info *info;

	printk("%s starting ...\n", __func__);

	if(!vma || !vmf){
		printk("%s invalid parameters\n", __func__);
		return VM_FAULT_SIGBUS;
	}

	if(address > vma->vm_end || address < vma->vm_start) {
                printk("%s invalid address\n", __func__);
                return VM_FAULT_SIGBUS;
        }

	/* the data is in vma->vm_private_data */
        info = (struct mmap_info *)vma->vm_private_data;
        if (!info || !info->data) {
                printk("%s no data\n", __func__);    
                return VM_FAULT_SIGBUS;            
        }

	printk("%s info is at: va %p phy_addr %pa\n", __func__, info->data,  virt_to_phys(info->data));
	
	 /* get the page */              
        page = virt_to_page(info->data + (vmf->pgoff*PAGE_SIZE));
        
        /* increment the reference count of this page */
        get_page(page);
          
        vmf->page= page;

	return 0;


}

struct vm_operations_struct mmap_vm_ops = {
	.open =     mmap_open,
	.close =    mmap_close,
	//.nopage =   mmap_nopage,
	.fault= mmap_fault,
};

int my_mmap(struct file *filp, struct vm_area_struct *vma){
	vma->vm_ops = &mmap_vm_ops;
	vma->vm_flags |= VM_RESERVED;
	/* assign the file private data to the vm private data */
	printk("%s: mapping vma\n", __func__);
	vma->vm_private_data = filp->private_data;
	mmap_open(vma);
	return 0;
}

int my_close(struct inode *inode, struct file *filp)
{
	struct mmap_info *info = filp->private_data;
	if(!info){
		printk("WARNING no mmap_info\n");
		return 0;
	}

	iounmap(info->data);
    	kfree(info);
	filp->private_data = NULL;
	return 0;
}

int my_open(struct inode *inode, struct file *filp)
{	
	unsigned long size= primary_dmesg_size;
	struct mmap_info *info;
	char * primary_dmesg; 

	info = kmalloc(sizeof(struct mmap_info), GFP_KERNEL);
	if(!info)
		return -ENOMEM;

	//address gnd size got from dmesg at boot time of primary
	primary_dmesg= ioremap_cache(primary_dmesg_buf_phys_addr, primary_dmesg_size);
  	//primary_dmesg= kmalloc(size, GFP_KERNEL);
	if(!primary_dmesg)
                return -ENOMEM;

	printk("%s: ioremap successfull va %p phy_addr %pa.    primary_dmesg_buf_phys_addr %pa primary_dmesg_buf_phys_addr aligned %pa primary_dmesg_size %d size %lu\n", __func__, primary_dmesg,  virt_to_phys(primary_dmesg), primary_dmesg_buf_phys_addr, primary_dmesg_buf_phys_addr&PAGE_MASK, primary_dmesg_size, size);

	iounmap(primary_dmesg);
	
	primary_dmesg= ioremap_cache(primary_dmesg_buf_phys_addr&PAGE_MASK, primary_dmesg_size);
        //primary_dmesg= kmalloc(size, GFP_KERNEL);
        if(!primary_dmesg)
                return -ENOMEM;

        printk("%s: ioremap successfull va %p phy_addr %pa.    primary_dmesg_buf_phys_addr %pa primary_dmesg_buf_phys_addr aligned %pa primary_dmesg_size %d size %lu\n", __func__, primary_dmesg,  virt_to_phys(primary_dmesg), primary_dmesg_buf_phys_addr, primary_dmesg_buf_phys_addr&PAGE_MASK, primary_dmesg_size, size);

        iounmap(primary_dmesg);

	 primary_dmesg= ioremap_cache(primary_dmesg_buf_phys_addr&PAGE_MASK, PAGE_SIZE);
        //primary_dmesg= kmalloc(size, GFP_KERNEL);
        if(!primary_dmesg)
                return -ENOMEM;

        printk("%s: ioremap successfull va %p phy_addr %pa.    primary_dmesg_buf_phys_addr %pa primary_dmesg_buf_phys_addr aligned %pa primary_dmesg_size %d size %lu\n", __func__, primary_dmesg,  virt_to_phys(primary_dmesg), primary_dmesg_buf_phys_addr, primary_dmesg_buf_phys_addr&PAGE_MASK, primary_dmesg_size, size);

        iounmap(primary_dmesg);

	 primary_dmesg= ioremap_cache(primary_dmesg_buf_phys_addr, PAGE_SIZE);
        //primary_dmesg= kmalloc(size, GFP_KERNEL);
        if(!primary_dmesg)
                return -ENOMEM;

        printk("%s: ioremap successfull va %p phy_addr %pa.    primary_dmesg_buf_phys_addr %pa primary_dmesg_buf_phys_addr aligned %pa primary_dmesg_size %d size %lu\n", __func__, primary_dmesg,  virt_to_phys(primary_dmesg), primary_dmesg_buf_phys_addr, primary_dmesg_buf_phys_addr&PAGE_MASK, primary_dmesg_size, size);

        iounmap(primary_dmesg);
	
	primary_dmesg= ioremap_cache(primary_dmesg_pfn << PAGE_SHIFT, PAGE_SIZE);
        //primary_dmesg= kmalloc(size, GFP_KERNEL);
        if(!primary_dmesg)
                return -ENOMEM;

        printk("%s: ioremap successfull va %p phy_addr %pa.    primary_dmesg_buf_phys_addr %pa primary_dmesg_buf_phys_addr aligned %pa primary_dmesg_size %d size %lu\n", __func__, primary_dmesg,  virt_to_phys(primary_dmesg), primary_dmesg_buf_phys_addr, primary_dmesg_buf_phys_addr&PAGE_MASK, primary_dmesg_size, size);



	info->reference= 0;
    	info->data = (char *)primary_dmesg;
	/* assign this info struct to the file */
	filp->private_data = info;
	return 0;
}

static const struct file_operations my_fops = {
	.open = my_open,
	.release = my_close,
	.mmap = my_mmap,
};


static void remap_dmesg_primary(void){

	file1 = debugfs_create_file("dmesg_primary", 0644, NULL, NULL, &my_fops);	
	
}


unsigned int inet_addr(char *str)
{
    int a, b, c, d;
    char arr[4];
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int *)arr;
}

void print_time(unsigned long long time[], int size_time){
	char tbuf[50];
	unsigned tlen;
	unsigned long nanosec_rem;
 	int i;
 
	for(i=0; i<size_time; i++){
		nanosec_rem = do_div(time[i], 1000000000);
        	tlen = sprintf(tbuf, "[%5lu.%06lu] ", (unsigned long) time[i], nanosec_rem / 1000);
		printk("time %d: %s\n", i, tbuf);
	}
	
}

void process_crash_kernel_notification(struct work_struct *work){
	struct pci_dev *dev;
	struct pci_dev *prev;
	int found, fd, offset;
	struct pci_bus *bus;
	mm_segment_t fs;
	struct ifreq ifr;
	struct socket *sock;
	unsigned int *addr;
	unsigned long long time[7];
	unsigned long long start_up,start_addr;
	
	trace_printk("\n");
	//0=> func total time 
	time[0]= cpu_clock(_cpu);

	kfree(work);

	//1=> scan bus time
	time[1]= cpu_clock(_cpu);

	//reenable device
        pci_dev_list_remove(0,"0x8086","0x10c9","0.0","", 0);

        bus = NULL;
        while ((bus = pci_find_next_bus(bus)) != NULL)
                         pci_rescan_bus(bus);

	time[1]= cpu_clock(_cpu)- time[1];

	//2=> find device
	time[2]= cpu_clock(_cpu);

	//scan the buses to activate the device
        dev= NULL;
        prev= NULL;
        found= 0;
        do{
                dev= pci_get_device(0x8086, 0x10c9, prev);
                if( dev && (PCI_SLOT(dev->devfn)== 0 && (PCI_FUNC(dev->devfn)== 0)))
                        found= 1;
                prev= dev;

        }while(dev!= NULL && !found);
	time[2]= cpu_clock(_cpu)- time[2];

        if(!dev){
                printk("ERROR: %s device not found\n", __func__);
                return;
        }

        if(!dev->driver){
                printk("ERROR: %s driver not found\n", __func__);
                return;
        }

	if(flush_pending_pckt_in_filters()){
		printk("ERROR: %s impossible to flush filters\n", __func__);
                return;
	}	

	printk("filters flushed\n");
	
	if(trim_stable_buffer_in_filters()){
		printk("ERROR: %s impossible to trim filters\n", __func__);
                return;
	}	
	printk("stable buffer trimmed\n");

	if(flush_send_buffer_in_filters()){
                printk("ERROR: %s impossible to flush send buffers\n", __func__);
                return;
        }
        printk("send buffer flushed\n");
	
	//set the net device up
	//the idea is to emulate what ifconfig does
	//ifconfig eth1 up
	//ifconfig eth1 10.1.1.40

	//NOTE for now net dev name (eth1) and desired address (10.1.1.48) are hardcoded
	//TODO extract dev name from net_dev

	//3=> create socket
	time[3]= cpu_clock(_cpu);

	sock= NULL;
	fd= sock_create_kern( PF_INET, SOCK_DGRAM, IPPROTO_IP, &sock);
	if(!sock || !sock->ops ||  !sock->ops->ioctl){
		printk("ERROR: %s impossible create socket\n", __func__);
		return;
	}
	time[3]= cpu_clock(_cpu)- time[3];

	//4=> eth up

	time[4]= cpu_clock(_cpu);
        start_up= time[4];

	//fs needs to be changed to be able to call ioctl from kernel space
	// (it is supposed to be called througth a system_call)

        fs = get_fs();     /* save previous value */
        set_fs (get_ds()); /* use kernel limit */

	memset(&ifr,0,sizeof(ifr));
        
        memcpy(ifr.ifr_name, "eth1", sizeof("eth1"));
        ifr.ifr_addr.sa_family= (sa_family_t) AF_INET;

        ifr.ifr_flags= IFF_UP|IFF_BROADCAST|IFF_RUNNING;

        sock->ops->ioctl(sock,  SIOCSIFFLAGS, (long unsigned int)&ifr);

	time[4]= cpu_clock(_cpu)- time[4];

	//5=> set eth addr
	time[5]= cpu_clock(_cpu);
	start_addr= time[5];

	memset(&ifr,0,sizeof(ifr));
        
	memcpy(ifr.ifr_name, "eth1", sizeof("eth1"));
        ifr.ifr_addr.sa_family= (sa_family_t) AF_INET;
	//the first unsigned short of sa_data is supposed to be the port
	offset= sizeof(unsigned short);
	addr= (unsigned int*) (ifr.ifr_addr.sa_data+offset);
	*addr= inet_addr("10.1.1.48");

	trace_printk("setting up ip\n");
	sock->ops->ioctl(sock, SIOCSIFADDR, (long unsigned int)&ifr);	
	trace_printk("ip set up called\n");
  
	set_fs(fs); /* restore before returning to user space */	
	
	time[5]= cpu_clock(_cpu)- time[5];
	//printk("network up\n");

	/*if(flush_send_buffer_in_filters()){
                printk("ERROR: %s impossible to flush send buffers\n", __func__);
                return;
        }*/

	update_replica_type_after_failure();
	trace_printk("replica type updated\n");

	//5=> dummy driver down
        time[6]= cpu_clock(_cpu);

	fs = get_fs();     /* save previous value */
        set_fs (get_ds()); /* use kernel limit */

        memset(&ifr,0,sizeof(ifr));

        memcpy(ifr.ifr_name, DUMMY_DRIVER, sizeof(DUMMY_DRIVER));
        ifr.ifr_addr.sa_family= (sa_family_t) AF_INET;

        ifr.ifr_flags= IFF_BROADCAST|IFF_RUNNING|IFF_MULTICAST;

        sock->ops->ioctl(sock,  SIOCSIFFLAGS, (long unsigned int)&ifr);
        
        set_fs(fs); /* restore before returning to user space */

        time[6]= cpu_clock(_cpu)- time[6];
	
	//printk("dummy_driver down\n");

	flush_syscall_info();
	trace_printk("syscall info updated\n");

	time[0]= cpu_clock(_cpu)- time[0];
	
	print_time(time, 7);
	printk("start_up: ");
	print_time(&start_up, 1);
	printk("start_addr: ");
	print_time(&start_addr, 1);

	//remap_dmesg_primary();
	return;
}

static int handle_crash_kernel_notification(struct pcn_kmsg_message* inc_msg){
	struct work_struct* work;
	struct crash_kernel_notification_msg *msg= (struct crash_kernel_notification_msg *)inc_msg;

	primary_dmesg_buf_phys_addr= msg->dmesg_buf_phys_addr;
	primary_dmesg_size= msg->dmesg_size;
	
	work= kmalloc(sizeof(*work), GFP_ATOMIC);
	if(!work)
		return -1;

	INIT_WORK(work, process_crash_kernel_notification);
        queue_work(crash_wq, work);

	pcn_kmsg_free_msg(inc_msg);

	return 0;
}

extern resource_size_t get_dmesg_log_buf_phy(void);

extern int get_dmesg_size(void);

extern unsigned long get_pfn_dmesg(void);

static void send_crash_kernel_msg(void){
	int i;
	struct crash_kernel_notification_msg *msg;

	msg= kmalloc(sizeof(*msg), GFP_KERNEL);
	if(!msg)
		return;
	
	msg->header.type= PCN_KMGS_TYPE_FT_CRASH_KERNEL;
	msg->header.prio= PCN_KMSG_PRIO_NORMAL;
	
	msg->dmesg_buf_phys_addr= get_dmesg_log_buf_phy();
	msg->dmesg_size= get_dmesg_size();
	msg->dmesg_pfn= get_pfn_dmesg();
#ifndef SUPPORT_FOR_CLUSTERING
        for(i = 0; i < NR_CPUS; i++) {

                if(i == _cpu) continue;
#else
        // the list does not include the current processor group descirptor (TODO)
        struct list_head *iter= NULL;
        _remote_cpu_info_list_t *objPtr= NULL;
        extern struct list_head rlist_head;
        list_for_each(iter, &rlist_head) {
                objPtr = list_entry(iter, _remote_cpu_info_list_t, cpu_list_member);
                i = objPtr->_data._processor;
#endif
		
		pcn_kmsg_send(i,(struct pcn_kmsg_message*) msg);
	}

	kfree(msg);

}

static void hang_cpu(void){
	asm volatile("cli": : :"memory");
 	asm volatile("hlt": : :"memory"); 
}

asmlinkage long sys_ft_crash_kernel(void)
{
       	if(ft_is_replicated(current)){
		if(ft_is_primary_replica(current)){
			printk("%s called\n", __func__);
			//local_bh_disable();
			//send message to all kernel to notify them that this one is crashing
			//this should be automatically detected from other kernels using heartbeat
			smp_send_stop();
			send_crash_kernel_msg();
			//send_zero_window_in_filters();
			//hang the cpu (for now I am assuming the kernel is running on a single core
			hang_cpu();

			//if here something went wrong	
			printk("ERROR: %s out from hang cpu\n", __func__);						
		}
	}

	return 0;
}

static int __init ft_crash_kernel_init(void) {

        pcn_kmsg_register_callback(PCN_KMGS_TYPE_FT_CRASH_KERNEL, handle_crash_kernel_notification);
	crash_wq= create_singlethread_workqueue("crash_wq");

        return 0;
}

late_initcall(ft_crash_kernel_init);


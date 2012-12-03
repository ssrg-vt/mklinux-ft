
// mcomm.c
// Copyright Antonio Barbalace, Virginia Tech 2012

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/mm.h>

#include <linux/smp.h>

//#define MAX_CPUS 64
//#define MAX_ARRAY MAX_CPUS
//#define MAX_BITMAP 4

//#if (WORLD_BYTES == 4)
// #define BIT_PER_BITMASK 32
//#else
#define BIT_PER_BITMASK 64
//#endif

#include <linux/mcomm.h>
#define USE_MBUFFER
#include <linux/bbuffer.h>
#ifdef USE_MBUFFER
 #include <linux/mbuffer.h>
#endif /* USE_MBUFFER */

/////////////////////////////////////////////////////////////////////
// bitmask support
/////////////////////////////////////////////////////////////////////

//typedef unsigned int bitmask_t;

static inline void clear_bit_bitmap(bitmask_t* pbitmap, int id)
{
	pbitmap[(id / BIT_PER_BITMASK)] &= ~(1 << (id % BIT_PER_BITMASK));
}

static inline void set_bit_bitmap(bitmask_t* pbitmap, int id)
{
	pbitmap[(id / BIT_PER_BITMASK)] |= (1 << (id % BIT_PER_BITMASK));
}

static inline int ffs_bit_bitmap(bitmask_t* pbitmap)
{
	register int i, pos;
	for (i=0; i<MAX_BITMAP; i++)
		if ((pos = ffs(pbitmap[i])) > 0)
			return ((i*BIT_PER_BITMASK) + (pos -1));
	return -1;
}
/////////////////////////////////////////////////////////////////////

#include <linux/mcomm.h>

static unsigned long mcomm_address = 0x0000;

/////////////////////////////////////////////////////////////////////
// allocator
/////////////////////////////////////////////////////////////////////

#define get_node_from_cpu(id) 0

#define alloc_private(size, node) __alloc_private(size, node)
#define alloc_global(size) __alloc_on_node(size, -1)
#define alloc_on_node(size, node) __alloc_on_node(size, node)
#define free_on_node(addr) __free_on_node(addr)

// KRN SHM
#define INIT_SIZE 0x1000000
unsigned long alloc_size = INIT_SIZE;
unsigned long alloc_addr = 0xbadabada;

// KRN SHM
static int alloc_init(void* poff, int size)
{
	void * virtual_address;

    unsigned long pfn = (long) poff >> PAGE_SHIFT;
    unsigned long psize = (size) ? size : alloc_size;
    unsigned long node = -1, nid = -1; // TODO

    if (alloc_size != psize)
    	alloc_size = psize;

/* check if the memory is mapped in any zone of the current
 * kernel instance. In such a case the memory will not be mapped
 * because mapped in the memory page table array.
 */
    for_each_online_node(nid) {
            unsigned long start_pfn, end_pfn;
            start_pfn = node_start_pfn(nid);
            end_pfn = node_end_pfn(nid);
            if ((start_pfn <= pfn) && (pfn < end_pfn)) {
                    node = nid;
                    break; // node found continue
            }
    }

    if (node == -1) { // page never mapped (why?)
    	 virtual_address = ioremap_cache(
    			 (resource_size_t)((void *) poff), alloc_size);
    } else {
    	struct page *shared_page;
    	shared_page = pfn_to_page(pfn);
    	virtual_address = page_address(shared_page);
    	void * kmap_addr = kmap(shared_page);
    	printk(KERN_INFO "%s: pages were mapped! page_address %p kmap_addr %p",
    			__func__, virtual_address, kmap_addr);
    }

    alloc_addr = (unsigned long)virtual_address; // set the allocated address to the virtual address

    printk(KERN_ALERT "%s: poff %p vaddr 0x%lx size %lu (0x%lx)\n",
    		__func__, poff, alloc_addr, alloc_size, alloc_size);

    if (alloc_addr)
    	return 0;
    else
    	return -1;
}

void* __alloc_on_node(size_t size, int node)
{
	int asize = 0x100000; // TODO check, improve and determine the size
	int anode = node +1;
	void* shmaddr = (void*)(alloc_addr +
			(unsigned long)(anode * asize));

	if (size > asize) {
		printk(KERN_ERR "%s: size %ld node %d asize %d ERROR\n",
				__func__, size, node, asize);
		return 0;
	}

	return shmaddr;
}

// do not use shared memory (local copy on private memory
void* __alloc_private(size_t size, int node) {
        return kmalloc(size, GFP_KERNEL);
}

/////////////////////////////////////////////////////////////////////


/// matrix memory

static int matrix_init_matrix (matrix_comm ** pmatrix, int elements)
{
	char matrix_magic[]= MAGIC_CHARS_MATR;
	int need_init =0;

	// actual matrix that takes care about the mapping
	//matrix_comm * matrix = (matrix_comm *)alloc_global(sizeof(matrix_comm));
	matrix_comm * matrix = (matrix_comm *)alloc_global(sizeof(matrix_comm));
	if (!matrix) {
		printk(KERN_ERR "%s: error allocating matrix_comm\n",
				__func__);
 		return -1;
	}

	// check if the area was allocated before
	if ( memcmp(matrix, matrix_magic, 4) == 0) {
		// it was initialized before, sanity checks
		if (matrix->elements != elements) {
			printk(KERN_ERR "%s: matrix elements not correspond %d %d\n",
					__func__, matrix->elements, elements);
			return -1;
		}
	}
	else {
		// it was never initialized before,
		need_init =1;

		//Initialize the main matrix descriptor
		memcpy(matrix, matrix_magic, 4);
		matrix->elements = elements;
		matrix->lock = 0;
		memset (&(matrix->present), 0, sizeof(bitmask_t));
		memset (&(matrix->desc[0]), 0, sizeof(void*) * elements);
	}

	if (pmatrix)
		*pmatrix = matrix;

	return need_init;
}

static int matrix_init_row (row_comm ** prow, matrix_comm * matrix,
		int size, int need_init, int id, int elements)
{
	char row_magic[]= MAGIC_CHARS_ROW;
	int l;
	int need_init_cell =0;

	/* this code will not use bbuffer_init */
	int bbuf_pad_size = size;
#ifdef CACHE_ALIGNED
	bbuf_pad_size = BBUFFER_SPACE(size);
#endif /* CACHE_ALIGNED */
	printk("%s: bbuf_pad_size 0x%x buffer_limit 0x%lx\n",
			__func__, bbuf_pad_size, (unsigned long)BBUFFER_LIMIT);
	BBUFFER_CHECK(bbuf_pad_size);

	/* for each cpu there is a vector of recveirs buffers */
	int bbuf_size = BBUFFER_SIZEOF(bbuf_pad_size);
	int row_memory =
			sizeof(row_comm) + (bbuf_size * elements);


	// we need to pass the cpuid in order to get the right shm area
	// is the alloc function that has to figure out the correct mem zone
	row_comm * row = (row_comm * ) alloc_on_node(row_memory, id);
	if ( !(row) ) {
		printk(KERN_ERR"%s: error allocating row_comm\n",
				__func__);
		return 0;
	}
	printk("%s: row_memory %d (0x%x) id %d row %p\n",
			__func__, row_memory, row_memory, id, row);
	CHECK_CACHE_ALIGNED(row);
	matrix->desc[id] = row; // TODO

	// if init is not required check if the area was allocated before
	if ( !need_init && (memcmp(row, row_magic, 4) == 0)) {
		need_init_cell=0;

		// it was initialized before, sanity checks
		if (row->elements != elements) {
			printk(KERN_ERR "%s: row elements not correspond %d %d\n",
					__func__, row->elements, elements);
			return 0;
		}
		if (row->csize != bbuf_size) {
			printk(KERN_ERR "%s: size not correspond %d %d\n",
					__func__, row->csize, bbuf_size);
			return 0;
		}
	}
	else {
		// it was never initialized before
		need_init_cell =1;

		memcpy(row, row_magic, 4);
		row->elements = elements;
		row->id = id;
		row->lock = 0;

		memset(&(row->status), 0, sizeof(bitmask_t) * MAX_BITMAP);
		memset(&(row->active), 0, sizeof(bitmask_t) * MAX_BITMAP);
		memset(&(row->offset), 0, sizeof(unsigned long) * MAX_ELEMENTS);

		row->csize = bbuf_size;
		row->cnumber = 0;
	}

	// check the alignment
	printk("%s: row_status %p row %p\n",
			__func__, &(row->status), &(row[1]));
	CHECK_CACHE_ALIGNED( (&(row->status)) );

	bbuffer_t * pbbuf = (bbuffer_t*)&(row[1]);
	CHECK_CACHE_ALIGNED( pbbuf );

	// init local data structures if required
	if (need_init_cell)
		for (l=0; l<elements; l++) {
			BBUFFER_INIT(pbbuf, bbuf_pad_size);

			row->offset[l] =
					(unsigned long)pbbuf - (unsigned long)((bbuffer_t*)&(row[1]));
			pbbuf = (bbuffer_t*)((void*)pbbuf + bbuf_size);

			set_bit_bitmap(&(row->active[0]), l);
		}

	if (prow)
		*prow = row;

	return need_init_cell;
}

/*
 * size is the size of a single message cell buffer
 * elements is the maximum number of rows or columns
 *
 * The returned value refer to a private local comm_mapping struct
 * such data structure saves the mappings of the different memory areas
 */
comm_mapping * matrix_init_mapping (int size, int elements )
{
	int i;
	int need_init =0;

	matrix_comm * matrix;

	/* arguments checks */
	if ((elements < 1) || (elements > MAX_CPUS) || !(size))
		return 0;

	need_init = matrix_init_matrix( &matrix, elements);
	if (need_init == -1)
		return 0;

	// create a comm_mapping descriptor
	comm_mapping * map = (comm_mapping*)
			alloc_private(sizeof(comm_mapping), -1);
	if (!map) {
		printk(KERN_ERR "%s: error allocating comm_mapping id %d\n",
				__func__, -1);
		return 0;
	}
	memset (map, 0, sizeof(comm_mapping));
	map->matrix = matrix;


	// allocate and init local data structures
	for (i=0; i<elements; i++) {

		row_comm * row = 0;
		int need_init_cell = matrix_init_row (&row, matrix,
						size, need_init, i, elements);
		if ( need_init_cell == -1 )
			return 0;

		// save the private mapping
		map->row[i] = row;
		map->bmp[i] = &(row->status[0]);
		map->buf[i] = (bbuffer_t *) &(row[1]);

		// set the global descriptor
		set_bit_bitmap(&(matrix->present[0]), i); // TODO move this to next function?
	}

	return map;
}

/*
 * This function assumes that a previous call to matrix_init_mapping was issued
 * and the shared data areas are mapped to memory (shared data areas corrensponds to
 * MPICH segments
 */
comm_buffers * matrix_init_buffers(comm_mapping * map, int id)
{
	int i;
	int elements =0, bbuf_size =0;


	/* arguments checks */
	if ( !(map) || (id < 0) || (id >= MAX_CPUS) )
		return 0;
	if ( !(map->matrix) || !(map->row[id]) )
		return 0;


	/* reload the arguments */
	elements = map->matrix->elements;
    printk("mcomm: matrix_init_buffers - map->matrix->elements: %d\r\n", map->matrix->elements);
	bbuf_size = map->row[id]->csize;

	/* create a comm_buffers descriptor */
	comm_buffers * buffs = (comm_buffers*)
			alloc_private(sizeof(comm_buffers), id);
	if (!buffs) {
		printk(KERN_ERR "%s: error allocating comm_buffers id %d\n",
				__func__, id);
		return 0;
	}
	memset(buffs, 0, sizeof(comm_buffers));

	/* init the private data structure */
	buffs->id = id;
	buffs->elements = elements;
	buffs->recv_bmp = map->bmp[id];

	/* cells of this row */
	for (i=0; i<elements; i++)
		buffs->recv_buf[i] = (void*) map->buf[id] + (bbuf_size * i);

	/* cross references */
	for (i=0; i<elements; i++) {
		buffs->send[i].bmp = map->bmp[i];
		buffs->send[i].buf = (void*) map->buf[i] + (bbuf_size * id);
	}

	return buffs;
}

// point to point send
int matrix_send_to(comm_buffers * buffs, int dest, char* buff, int count)
{
	register bbuffer_t * bb;

	/* check if the vector is valid */
	if (!buffs) {
        printk("mcomm: matrix_send_to - buffs invalid\r\n");
		return 0;
    }
	/* check if the cpu is in range */
	if (!(dest < buffs->elements)) {
        printk("mcomm: matrix_send_to - cpu out of range. Dst: %d, Elements: %d\r\n",dest,buffs->elements);
		return 0;
    }
	/* check if the destination recv buffer is registered */
	if (!(bb = buffs->send[dest].buf)) {
        printk("mcomm: matrix_send_to - destination recv buffer not registered\r\n");
		return 0;
    }

	register int a;
#ifdef USE_MBUFFER
	a = mbuffer_put(bb, buff, count);
#else
	a = bbuffer_put(bb, buff, count);
#endif

	if (a > 0)
		set_bit_bitmap(buffs->send[dest].bmp, buffs->id);
	return a;
}

int matrix_send_self(comm_buffers * buffs, char* buff, int count)
{
	if ( !buffs )
		return 0;

	return matrix_send_to(buffs, buffs->id, buff, count);
}

// point to point recv functions

int matrix_recv_from(comm_buffers* buffs, int src, char* buff, int count)
{
	register bbuffer_t * bb;

	/* check if the vector is valid */
	if (!buffs)
		return 0;
	/* check if the cpu is in range */
	if (!(src < buffs->elements))
		return 0;
	/* check if our recv buffer is registered */
	if (!(bb = buffs->recv_buf[src]))
		return 0;

	// we choose to do not use the bitmap here but only as a best

	register int a;
#ifdef USE_MBUFFER
	a = mbuffer_get(bb, buff, count);
#else
	a = bbuffer_get(bb, buff, count);
#endif

	if (a > 0)
		if (!bbuffer_count(bb))
			clear_bit_bitmap(buffs->recv_bmp, src);
	return a;
}

int matrix_recv_self(comm_buffers* buffs, char* buff, int count)
{
	return matrix_recv_from(buffs, buffs->id, buff, count);
}

static comm_mapping* cmap;
static comm_buffers* cbuf;

#define COMM_BUFFS_SIZE 0x2000
#define COMM_CPU_NUM 8

static int __init mcomm_init(void)
{
	if ( !mcomm_address ) {
		printk(KERN_ERR"MATRIX Communicator @ 0x%lx. Cannot Initialize\n",
				mcomm_address);
		return -1;
	}

	printk("MATRIX Communicator @ 0x%lx cpuid %d. Initialization\n",
			mcomm_address, smp_processor_id());

	alloc_init((void*)mcomm_address, 0);

	cmap = matrix_init_mapping(COMM_BUFFS_SIZE, COMM_CPU_NUM);
	cbuf = matrix_init_buffers(cmap, smp_processor_id());

	printk("MATRIX Communicator cmap %p cbuf %p\n", cmap, cbuf);
	return 0;
}
__initcall(mcomm_init);


static int __init _mcomm_param(char *str)
{
	if (!str)
		return -EINVAL;

	mcomm_address = simple_strtoull(str, 0, 16);
	//mcomm_address = simple_strtoull(str, 0, 0); //automatically discover the base

    return 0;
}

early_param("mcomm", _mcomm_param);

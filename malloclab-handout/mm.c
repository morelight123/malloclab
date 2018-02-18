/*
 * mm.c
 * Auther: Kaixuan Meng; kbm5393
 * using 4 bytes header and footer with 16 bytes alignment to complete the design of malloc.
 * segregated_free_list is used to improve performance.
 * 
 *
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#include "mm.h"
#include "memlib.h"

/*
 * If you want debugging output, uncomment the following. Be sure not
 * to have debugging enabled in your final submission
 */
// #define DEBUG

#ifdef DEBUG
/* When debugging is enabled, the underlying functions get called */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated */
#define dbg_printf(...)
#define dbg_assert(...)
#endif /* DEBUG */

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#define memset mem_memset
#define memcpy mem_memcpy
#endif /* DRIVER */

/* What is the correct alignment? */
#define ALIGNMENT 16

/* rounds up to the nearest multiple of ALIGNMENT */
static size_t align(size_t x)
{
    return ALIGNMENT * ((x+ALIGNMENT-1)/ALIGNMENT);
}




struct HDR_FTR {		//header and FTR have 4 bytes
    unsigned short size;             
    bool hit_edge;
    bool free_or_not;         
} HDR_FTR;
typedef struct HDR_FTR* HDR;
typedef struct HDR_FTR* FTR;

typedef struct FREE_BLK_STRUCT* FREE_BLK;		//free block has totally 16 bytes
struct FREE_BLK_STRUCT {
    FREE_BLK NEXT_BLKP;    // point to the next block | 8 bytes
    FREE_BLK PREV_BLKP;    // point to the previous block | 8 bytes
} FREE_BLK_STRUCT;

// Function prototypes 
HDR HDRP(void *bp);
FTR FTRP(void *bp);
bool free_or_not(void *bp);
void set_prologue(void *bp);
void set_epilogue(void *bp);
void set_hdr_or_ftr(void *bp, size_t size, bool free);
void remove_freed_block(FREE_BLK bp);
void insert_free_block(void *bp);
void set_free_blk_data(void *bp, FREE_BLK NEXT_BLKP, FREE_BLK PREV_BLKP);


//Global val
const size_t PTR_SIZE=8;
const size_t HEAD_SIZE=4;
static char* heap_head;
static FREE_BLK segregated_free_list;
static int SEARCH_TIME=30;
const size_t INIT_BLOCK_SIZE=1<<7;
const size_t MINIMUM_BLK_SIZE=16+4+4;//alignment + header + footer
#ifdef DEBUG
static int count=0;
#endif


/*static void PUT(size_t *p,size_t val) {*(size_t *)(p)=val;}
static size_t GET(size_t *p) {return (*(size_t *)(p));}
static size_t Max(size_t x, size_t y) {return (x) > (y)? (x) : (y);}
static size_t GET_SIZE(void * p) {return GET(p)&(~0x15);}
static size_t GET_ALLOC(void * p) {return GET(p)&0x1;}*/
static size_t Max(size_t x, size_t y) {return (x) > (y)? (x) : (y);}

//get block size
size_t GET_SIZE(void *bp){return (HDRP(bp)->size) << (PTR_SIZE-HEAD_SIZE);}

//get the address of header and footer
HDR HDRP(void *bp){return (HDR)((char*)bp - HEAD_SIZE);}
FTR FTRP(void *bp){return (FTR)((char*)bp + GET_SIZE(bp) - PTR_SIZE);}

//check for availability
bool free_or_not(void *bp){return HDRP(bp)->free_or_not;}

//insert prologue
void set_prologue(void *bp){
    struct HDR_FTR prologue = {PTR_SIZE, true, false};
    *(HDR)(bp) = prologue;                 // prologue header
    *(FTR)(bp + HEAD_SIZE) = prologue;   // prologue FTR
}
//insert epilogue
void set_epilogue(void *bp){*(HDR)bp = (struct HDR_FTR){0, true, false};}

//next & prev blk
void *NEXT_BLK(void *bp){return (char *)bp + GET_SIZE(bp);}
void *PREV_BLK(void *bp){
    FTR PREV_FTR = (FTR)(bp - PTR_SIZE);
    if (PREV_FTR->hit_edge==true)	
	return PREV_FTR - 1;
    else {
	return (char*)bp - ((PREV_FTR->size) << (PTR_SIZE-HEAD_SIZE));
    }
}
//set value into header and footer
void set_hdr_or_ftr(void *bp, size_t s, bool free){
    short size = (unsigned short)(s>>(PTR_SIZE-HEAD_SIZE));
    *HDRP(bp) = (struct HDR_FTR){size,false,free};
    *FTRP(bp) = (struct HDR_FTR){size,false,free};
}

void set_free_blk_data(void *bp, FREE_BLK NEXT_BLKP, FREE_BLK PREV_BLKP){
    *(FREE_BLK)bp = (struct FREE_BLK_STRUCT){NEXT_BLKP, PREV_BLKP};
}

//insert a new free block into the head of free_blk_list
void insert_free_block(void *bp) {
    set_free_blk_data(bp, segregated_free_list, NULL);
    if (segregated_free_list)	
	segregated_free_list->PREV_BLKP = bp;
    segregated_free_list = bp;
}

//remove a non-free block in the list
void remove_freed_block(FREE_BLK bp) {

	if (bp->PREV_BLKP==NULL){//special case: last free block in the list
		if (bp->NEXT_BLKP==NULL) {
			segregated_free_list=NULL;
			return;
		}
		else{//set next block as the head of free list
			bp->NEXT_BLKP->PREV_BLKP=NULL;
			segregated_free_list=bp->NEXT_BLKP;
			return;
		}
	}
	else {//remove block at the end of the list
		if (bp->NEXT_BLKP==NULL) {
			bp->PREV_BLKP->NEXT_BLKP=NULL;
			return;}
		else {//remove blk in the middle of list
			bp->NEXT_BLKP->PREV_BLKP=bp->PREV_BLKP;
			bp->PREV_BLKP->NEXT_BLKP=bp->NEXT_BLKP;
			return;
		}
	}
}

//find a better fit for a malloc block
FREE_BLK bestfit(size_t size) {
    FREE_BLK bp = segregated_free_list;
    if(bp==NULL)
	return NULL;
    FREE_BLK candidate = NULL;
    size_t best_size = 0;
    int count=0;
    while(count<SEARCH_TIME) {
	if(bp==NULL)
	    break;
        if (GET_SIZE(bp) >= size){
	    //if(candidate==NULL)
		//candidate = bp;
            if (GET_SIZE(bp) <= best_size||candidate==NULL){
                candidate = bp;
                best_size = GET_SIZE(bp);
            }
        }
        bp = bp->NEXT_BLKP;//try next blk
	count++;
    }
    return candidate;
}



//utilize space when data cant fill all the space
void *split(FREE_BLK bp, size_t asize) {
    size_t block_size = GET_SIZE(bp);
    size_t free_space = block_size - asize;
    remove_freed_block(bp);
    if (free_space<= (PTR_SIZE + ALIGNMENT)){
        set_hdr_or_ftr(bp, block_size, false);
    }
    else {
        set_hdr_or_ftr(bp, asize, false);
        set_hdr_or_ftr(NEXT_BLK(bp), free_space, true);
        insert_free_block(NEXT_BLK(bp));
    }

    return bp;
}

//check for adjacent free space, if any, combine to form a big one. Utilization
void *coalesce(FREE_BLK bp) {
    size_t size = GET_SIZE(bp);
    bool prev_free = free_or_not(PREV_BLK(bp));
    bool next_free = free_or_not(NEXT_BLK(bp));
    size_t largeSize = GET_SIZE(PREV_BLK(bp))+GET_SIZE(NEXT_BLK(bp))+size;

    if (!prev_free && !next_free)
	return bp;
    else if ((prev_free && !next_free) || ((next_free && prev_free)&&largeSize > (0xFFFF << (PTR_SIZE-HEAD_SIZE)))) {
        size+=GET_SIZE(PREV_BLK(bp));
        if (size >= (0xFFFF << HEAD_SIZE)) {	
		return bp;}
        remove_freed_block(bp);
        remove_freed_block(PREV_BLK(bp));
        set_hdr_or_ftr(PREV_BLK(bp), size, true);
        bp = PREV_BLK(bp);
    }
    else if (!prev_free && next_free) {
        size += GET_SIZE(NEXT_BLK(bp));
        if (size >= (0xFFFF << HEAD_SIZE)) {
		return bp;}

        remove_freed_block(bp);
        remove_freed_block(NEXT_BLK(bp));
        set_hdr_or_ftr(bp, size, true);
    }
    else {
        size += GET_SIZE(NEXT_BLK(bp)) + GET_SIZE(PREV_BLK(bp));
        remove_freed_block(bp);
        remove_freed_block(NEXT_BLK(bp));
        remove_freed_block(PREV_BLK(bp));
        set_hdr_or_ftr(PREV_BLK(bp), size, true);
        bp = PREV_BLK(bp);
    }
    insert_free_block(bp);
    return bp;
}

void *extend_heap(size_t size){ 
    size_t asize = align(size);
    void *bp = mem_sbrk(asize); 
    if (bp == (void *) -1) {
	printf("extend heap fail\n");
	return NULL;}
    set_hdr_or_ftr(bp, asize, true);
    set_epilogue(NEXT_BLK(bp) - HEAD_SIZE);
    insert_free_block(bp);
    return coalesce(bp);
}


/*
 * Initialize: return false on error, true on success.
 */
bool mm_init(void)
{
    heap_head = NULL;
    heap_head = mem_sbrk(16);
    segregated_free_list = NULL;
    if (heap_head == (void *) -1) return false;

    *(unsigned int *)(heap_head) = 0;
    set_prologue((char*)heap_head + HEAD_SIZE);
    set_epilogue((char*)heap_head + HEAD_SIZE+PTR_SIZE);

    heap_head += 16;

    if (extend_heap(INIT_BLOCK_SIZE) == NULL) return false;
    else return true;
}

/*
 * malloc
 */
void* malloc(size_t size)
{
    FREE_BLK bp;
    size_t asize;

    if (size == 0) return NULL;

    if (size <= 24)	size = 24;
  
    asize = align(size + PTR_SIZE);
    bp = bestfit(asize);
    if (bp == NULL) {
        size_t extend_size;
        if (asize > 4096)	
	    extend_size = asize*3;
        else if (asize > 2048)	
	    extend_size = asize*2;
        else	
	    extend_size = 2048;
        bp = extend_heap(extend_size);
        if (bp == NULL)		
	    return NULL;
    }

    bp = split(bp, asize);
    return bp;
}

/*
 * free
 */
void free(void* ptr)
{
    size_t size = GET_SIZE(ptr);
    if (ptr == NULL) return;
    set_hdr_or_ftr(ptr, size, true);
    insert_free_block(ptr);
    coalesce(ptr);
    return;
}

/*
 * realloc
 */
void* realloc(void* old_bp, size_t size)
{
    void *new_bp;

    if (size == 0){
        free(old_bp);
        return NULL;
    }
    if (old_bp==NULL)	
	return malloc(size);
    if (size <= MINIMUM_BLK_SIZE)	
	size = MINIMUM_BLK_SIZE;
    new_bp = malloc(size);
    if (!new_bp)	
	return NULL;

    memcpy(new_bp, old_bp, size);
    free(old_bp);
    return new_bp;
}

/*
 * calloc
 * This function is not tested by mdriver, and has been implemented for you.
 */
void* calloc(size_t nmemb, size_t size)
{
    void* ret;
    size *= nmemb;
    ret = malloc(size);
    if (ret) {
        memset(ret, 0, size);
    }
    return ret;
}

/*
 * Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static bool in_heap(const void* p)
{
    return p <= mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static bool aligned(const void* p)
{
    size_t ip = (size_t) p;
    return align(ip) == ip;
}

/*
 * mm_checkheap
 */
bool mm_checkheap(int lineno)
{
    #ifdef DEBUG
    count++;
    int num = 0;
    void *bp;

    if (!count){
        for (bp = heap_head; HDRP(bp)->size != 0; bp = NEXT_BLK(bp)){
            if (bp == heap_head){
                printf("HEAP HEAD:\n");
                printBlock(bp);
                printf("\n");
                num = 0;
            }
            if((HDRP(bp)->size != FTRP(bp)->size)){
                printf("ERROR: SOMETHING WRONG WITH THE SIZE\n");
                printBlock(bp);
            }
            printf("Block %d: ", num);
            printBlock(bp);
            num++;
        }
    }
    #endif /* DEBUG */
    return true;
}
/*
static inline void printBlock(void *bp){    
    size_t hsize, halloc, fsize, falloc;    
    
    hsize = GET_SIZE(HDRP(bp));    
    halloc = GET_ALLOC(HDRP(bp));    
    fsize = GET_SIZE(FTRP(bp));    
    falloc = GET_ALLOC(FTRP(bp));    
    
    if (hsize == 0) {    
        printf("%p: EOL\n", bp);    
        return;    
    }    
    if (halloc)    
        printf("bp: %p: header: [%zu:%c:%c] footer: \n", bp, hsize, (GET_PREV_ALLOC(bp) ? 'a' : 'f'), (halloc ? 'a' : 'f'));    
    else    
    {    
        printf("bp: %p: header: [%zu:%c:%c] footer: [%zu:%c]\n", bp,hsize, (GET_PREV_ALLOC(bp) ? 'a' : 'f'), (halloc ? 'a' : 'f'),fsize, (falloc ? 'a' : 'f'));       
        if (PREV_BLK(bp))    
            printf("pb: %p\n", PREV_BLK(bp));    
        putchar('\n');    
    }    
} */   

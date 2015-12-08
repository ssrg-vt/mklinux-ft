/*
 * kmsg_core.h
 *
 *  Created on: Dec 7, 2015
 *      Author: root
 */

#ifndef PCNMSG_KMSG_CORE_H_
#define PCNMSG_KMSG_CORE_H_

/*****************************************************************************/
/* Debugging Macros */
/*****************************************************************************/

#define KMSG_VERBOSE 0
#if KMSG_VERBOSE
#define KMSG_PRINTK(fmt, args...) printk("%s: " fmt, __func__, ##args)
#else
#define KMSG_PRINTK(...) ;
#endif

#define MCAST_VERBOSE 0
#if MCAST_VERBOSE
#define MCAST_PRINTK(fmt, args...) printk("%s: " fmt, __func__, ##args)
#else
#define MCAST_PRINTK(...) ;
#endif

#define KMSG_INIT(fmt, args...) printk("KMSG INIT: %s: " fmt, __func__, ##args)
#define KMSG_ERR(fmt, args...) printk("%s: ERROR: " fmt, __func__, ##args)

#define PCN_DEBUG(...) ;
//#define PCN_WARN(...) printk(__VA_ARGS__)
#define PCN_WARN(...) ;
#define PCN_ERROR(...) printk(__VA_ARGS__)

/*****************************************************************************/
/* Logging Macros and variables */
/*****************************************************************************/

#define LOGLEN 4
#define LOGCALL 32

// TODO this stuff should be moved to ring-buffer because it is mostly about ring buffer 
extern struct pcn_kmsg_hdr log_receive[LOGLEN];
extern struct pcn_kmsg_hdr log_send[LOGLEN];
extern int log_r_index;
extern int log_s_index;

/* The followings should be ok to be left at higher level
void * log_function_called[LOGCALL];
int log_f_index;
int log_f_sendindex;
void * log_function_send[LOGCALL];
*/

/*****************************************************************************/
/* statistics */
/****************************************************************************/

extern unsigned long long total_sleep_win_put;
extern unsigned int sleep_win_put_count;
extern unsigned long long total_sleep_win_get;
extern unsigned int sleep_win_get_count;

extern long unsigned int msg_put;
extern long unsigned msg_get;


#endif /* PCNMSG_KMSG_CORE_H_ */

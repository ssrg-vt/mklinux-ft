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




#endif /* PCNMSG_KMSG_CORE_H_ */

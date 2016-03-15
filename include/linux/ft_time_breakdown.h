/* 
 * ft_time_breakdown.h  
 *
 * Author: Marina
 */

#ifndef FT_TIME_BREAKDOWN_H_
#define FT_TIME_BREAKDOWN_H_

#include <linux/types.h>

#define FT_BREAKDOWN_TIME 1

#define FT_TIME_HOOK_BEF_NET 0
#define FT_TIME_BEF_NET_REP 1
#define FT_TIME_HOOK_AFT_NET 2
#define FT_TIME_AFT_NET_REP 3
#define FT_TIME_HOOK_BEF_TRA 4
#define FT_TIME_BEF_TRA_REP 5
#define FT_TIME_HOOK_AFT_TRA 6
#define FT_TIME_AFT_TRA_REP 7

#define FT_TIME_SEND_PACKET_REP 8
#define FT_TIME_INJECT_RECV_PACKET 9
#define FT_TIME_INJECT_HANDSHACKE_PACKETS 10

#define TOT_TIME_SEND 11
#define TOT_TIME_RCV 12
#define TOT_TIME_POLL 13
#define TOT_TIME_319 14
#define TOT_TIME_320 15
#define TOT_TIME_ACCEPT 16

#define FT_TIME_SEND_SYCALL 17
#define FT_TIME_RCV_SYSCALL 18
#define FT_TIME_DET_START 19
#define FT_TIME_WAIT_BUMP 20
#define FT_TIME_SEND_BUMP 21

#define MAX_BREACKDOWNS 22

#if FT_BREAKDOWN_TIME

void ft_start_time(u64 *time);
void ft_end_time(u64 *time);
void ft_update_time(u64 *time, unsigned int type);
int print_ft_time_breakdown(void);

#else

static void inline ft_start_time(u64 *time){}
static void inline ft_end_time(u64 *time){}
static void inline ft_update_time(u64 *time, unsigned int type){}

#endif

#endif


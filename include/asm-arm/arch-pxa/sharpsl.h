/*
 * SharpSL SSP Driver
 */

unsigned long corgi_ssp_ads7846_putget(unsigned long);
unsigned long corgi_ssp_ads7846_get(void);
void corgi_ssp_ads7846_put(unsigned long data);
void corgi_ssp_ads7846_lock(void);
void corgi_ssp_ads7846_unlock(void);
void corgi_ssp_lcdtg_send (unsigned char adrs, unsigned char data);
void corgi_ssp_blduty_set(int duty);
int corgi_ssp_max1111_get(unsigned long data);

#ifndef BCM43xx_LEDS_H_
#define BCM43xx_LEDS_H_

#include <linux/types.h>
#include <linux/timer.h>


struct bcm43xx_led {
	u8 behaviour:7;
	u8 activelow:1;

	struct bcm43xx_private *bcm;
	struct timer_list blink_timer;
	unsigned long blink_interval;
};
#define bcm43xx_led_index(led)	((int)((led) - (led)->bcm->leds))

/* Delay between state changes when blinking in jiffies */
#define BCM43xx_LEDBLINK_SLOW		(HZ / 2)
#define BCM43xx_LEDBLINK_MEDIUM		(HZ / 4)
#define BCM43xx_LEDBLINK_FAST		(HZ / 8)

#define BCM43xx_LED_XFER_THRES		(HZ / 100)

#define BCM43xx_LED_BEHAVIOUR		0x7F
#define BCM43xx_LED_ACTIVELOW		0x80
enum { /* LED behaviour values */
	BCM43xx_LED_OFF,
	BCM43xx_LED_ON,
	BCM43xx_LED_ACTIVITY,
	BCM43xx_LED_RADIO_ALL,
	BCM43xx_LED_RADIO_A,
	BCM43xx_LED_RADIO_B,
	BCM43xx_LED_MODE_BG,
	BCM43xx_LED_TRANSFER,
	BCM43xx_LED_APTRANSFER,
	BCM43xx_LED_WEIRD,//FIXME
	BCM43xx_LED_ASSOC,
	BCM43xx_LED_INACTIVE,
};

int bcm43xx_leds_init(struct bcm43xx_private *bcm);
void bcm43xx_leds_exit(struct bcm43xx_private *bcm);
void bcm43xx_leds_update(struct bcm43xx_private *bcm, int activity);
void bcm43xx_leds_turn_off(struct bcm43xx_private *bcm);

#endif /* BCM43xx_LEDS_H_ */

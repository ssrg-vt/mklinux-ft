/**
  * This file contains definition for IOCTL call.
  */
#ifndef	_LBS_WEXT_H_
#define	_LBS_WEXT_H_

void lbs_send_disconnect_notification(struct lbs_private *priv);
void lbs_send_mic_failureevent(struct lbs_private *priv, u32 event);

extern struct iw_handler_def lbs_handler_def;
extern struct iw_handler_def mesh_handler_def;

#endif

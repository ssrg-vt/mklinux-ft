/**
  * Contains all definitions needed for the Libertas' MESH implementation.
  */
#ifndef _LBS_MESH_H_
#define _LBS_MESH_H_


#include <net/iw_handler.h>


/* Mesh statistics */
struct lbs_mesh_stats {
	u32	fwd_bcast_cnt;		/* Fwd: Broadcast counter */
	u32	fwd_unicast_cnt;	/* Fwd: Unicast counter */
	u32	fwd_drop_ttl;		/* Fwd: TTL zero */
	u32	fwd_drop_rbt;		/* Fwd: Recently Broadcasted */
	u32	fwd_drop_noroute; 	/* Fwd: No route to Destination */
	u32	fwd_drop_nobuf;		/* Fwd: Run out of internal buffers */
	u32	drop_blind;		/* Rx:  Dropped by blinding table */
	u32	tx_failed_cnt;		/* Tx:  Failed transmissions */
};


struct net_device;
struct lbs_private;

int lbs_init_mesh(struct lbs_private *priv);
int lbs_deinit_mesh(struct lbs_private *priv);

int lbs_add_mesh(struct lbs_private *priv);
void lbs_remove_mesh(struct lbs_private *priv);


/* Sending / Receiving */

struct rxpd;
struct txpd;

struct net_device *lbs_mesh_set_dev(struct lbs_private *priv,
	struct net_device *dev, struct rxpd *rxpd);
void lbs_mesh_set_txpd(struct lbs_private *priv,
	struct net_device *dev, struct txpd *txpd);


/* Persistent configuration */

void lbs_persist_config_init(struct net_device *net);
void lbs_persist_config_remove(struct net_device *net);


/* WEXT handler */

extern struct iw_handler_def mesh_handler_def;


#endif

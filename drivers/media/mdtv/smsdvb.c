#include <linux/module.h>
#include <linux/init.h>

#include "dmxdev.h"
#include "dvbdev.h"
#include "dvb_demux.h"
#include "dvb_frontend.h"

#include "smscoreapi.h"
#include "smstypes.h"

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

typedef struct _smsdvb_client
{
	struct list_head entry;

	smscore_device_t	*coredev;
	smscore_client_t	*smsclient;

	struct dvb_adapter	adapter;
	struct dvb_demux	demux;
	struct dmxdev		dmxdev;
	struct dvb_frontend	frontend;

	fe_status_t			fe_status;
	int					fe_ber, fe_snr, fe_signal_strength;

	struct completion	tune_done, stat_done;

	// todo: save freq/band instead whole struct
	struct dvb_frontend_parameters fe_params;

} smsdvb_client_t;

struct list_head g_smsdvb_clients;
kmutex_t g_smsdvb_clientslock;

int smsdvb_onresponse(void *context, smscore_buffer_t *cb)
{
	smsdvb_client_t *client = (smsdvb_client_t *) context;
	SmsMsgHdr_ST *phdr = (SmsMsgHdr_ST *)(((u8*) cb->p) + cb->offset);

	switch(phdr->msgType)
	{
		case MSG_SMS_DVBT_BDA_DATA:
			dvb_dmx_swfilter(&client->demux, (u8*)(phdr + 1), cb->size - sizeof(SmsMsgHdr_ST));
			break;

		case MSG_SMS_RF_TUNE_RES:
			complete(&client->tune_done);
			break;

		case MSG_SMS_GET_STATISTICS_RES:
		{
			SmsMsgStatisticsInfo_ST* p = (SmsMsgStatisticsInfo_ST*)(phdr + 1);

			if (p->Stat.IsDemodLocked)
			{
				client->fe_status = FE_HAS_SIGNAL | FE_HAS_CARRIER | FE_HAS_VITERBI | FE_HAS_SYNC | FE_HAS_LOCK;
				client->fe_snr = p->Stat.SNR;
				client->fe_ber = p->Stat.BER;

				if (p->Stat.InBandPwr < -95)
					client->fe_signal_strength = 0;
				else if (p->Stat.InBandPwr > -29)
					client->fe_signal_strength = 100;
				else
					client->fe_signal_strength = (p->Stat.InBandPwr + 95) * 3 / 2;
			}
			else
			{
				client->fe_status = 0;
				client->fe_snr =
				client->fe_ber =
				client->fe_signal_strength = 0;
			}

			complete(&client->stat_done);
			break;
		}
	}

	smscore_putbuffer(client->coredev, cb);

	return 0;
}

void smsdvb_unregister_client(smsdvb_client_t* client)
{
	// must be called under clientslock

	list_del(&client->entry);

	smscore_unregister_client(client->smsclient);
	dvb_unregister_frontend(&client->frontend);
	dvb_dmxdev_release(&client->dmxdev);
	dvb_dmx_release(&client->demux);
	dvb_unregister_adapter(&client->adapter);
	kfree(client);
}

void smsdvb_onremove(void *context)
{
	kmutex_lock(&g_smsdvb_clientslock);

	smsdvb_unregister_client((smsdvb_client_t*) context);

	kmutex_unlock(&g_smsdvb_clientslock);
}

static int smsdvb_start_feed(struct dvb_demux_feed *feed)
{
	smsdvb_client_t *client = container_of(feed->demux, smsdvb_client_t, demux);
	SmsMsgData_ST PidMsg;

	printk("%s add pid %d(%x)\n", __FUNCTION__, feed->pid, feed->pid);

	PidMsg.xMsgHeader.msgSrcId = DVBT_BDA_CONTROL_MSG_ID;
	PidMsg.xMsgHeader.msgDstId = HIF_TASK;
	PidMsg.xMsgHeader.msgFlags = 0;
	PidMsg.xMsgHeader.msgType  = MSG_SMS_ADD_PID_FILTER_REQ;
	PidMsg.xMsgHeader.msgLength = sizeof(PidMsg);
	PidMsg.msgData[0] = feed->pid;

	return smsclient_sendrequest(client->smsclient, &PidMsg, sizeof(PidMsg));
}

static int smsdvb_stop_feed(struct dvb_demux_feed *feed)
{
	smsdvb_client_t *client = container_of(feed->demux, smsdvb_client_t, demux);
	SmsMsgData_ST PidMsg;

	printk("%s remove pid %d(%x)\n", __FUNCTION__, feed->pid, feed->pid);

	PidMsg.xMsgHeader.msgSrcId = DVBT_BDA_CONTROL_MSG_ID;
	PidMsg.xMsgHeader.msgDstId = HIF_TASK;
	PidMsg.xMsgHeader.msgFlags = 0;
	PidMsg.xMsgHeader.msgType  = MSG_SMS_REMOVE_PID_FILTER_REQ;
	PidMsg.xMsgHeader.msgLength = sizeof(PidMsg);
	PidMsg.msgData[0] = feed->pid;

	return smsclient_sendrequest(client->smsclient, &PidMsg, sizeof(PidMsg));
}

static int smsdvb_sendrequest_and_wait(smsdvb_client_t *client, void* buffer, size_t size, struct completion *completion)
{
	int rc = smsclient_sendrequest(client->smsclient, buffer, size);
	if (rc < 0)
		return rc;

	return wait_for_completion_timeout(completion, msecs_to_jiffies(2000)) ? 0 : -ETIME;
}

static int smsdvb_send_statistics_request(smsdvb_client_t *client)
{
	SmsMsgHdr_ST Msg = { MSG_SMS_GET_STATISTICS_REQ, DVBT_BDA_CONTROL_MSG_ID, HIF_TASK, sizeof(SmsMsgHdr_ST), 0 };
	return smsdvb_sendrequest_and_wait(client, &Msg, sizeof(Msg), &client->stat_done);
}

static int smsdvb_read_status(struct dvb_frontend *fe, fe_status_t *stat)
{
	smsdvb_client_t *client = container_of(fe, smsdvb_client_t, frontend);
	int rc = smsdvb_send_statistics_request(client);

	if (!rc)
		*stat = client->fe_status;

	return rc;
}

static int smsdvb_read_ber(struct dvb_frontend *fe, u32 *ber)
{
	smsdvb_client_t *client = container_of(fe, smsdvb_client_t, frontend);
	int rc = smsdvb_send_statistics_request(client);

	if (!rc)
		*ber = client->fe_ber;

	return rc;
}

static int smsdvb_read_signal_strength(struct dvb_frontend *fe, u16 *strength)
{
	smsdvb_client_t *client = container_of(fe, smsdvb_client_t, frontend);
	int rc = smsdvb_send_statistics_request(client);

	if (!rc)
		*strength = client->fe_signal_strength;

	return rc;
}

static int smsdvb_read_snr(struct dvb_frontend *fe, u16 *snr)
{
	smsdvb_client_t *client = container_of(fe, smsdvb_client_t, frontend);
	int rc = smsdvb_send_statistics_request(client);

	if (!rc)
		*snr = client->fe_snr;

	return rc;
}

static int smsdvb_get_tune_settings(struct dvb_frontend *fe, struct dvb_frontend_tune_settings *tune)
{
	printk("%s\n", __FUNCTION__);

	tune->min_delay_ms = 400;
	tune->step_size = 250000;
	tune->max_drift = 0;
	return 0;
}

static int smsdvb_set_frontend(struct dvb_frontend *fe, struct dvb_frontend_parameters *fep)
{
	smsdvb_client_t *client = container_of(fe, smsdvb_client_t, frontend);

	struct
	{
		SmsMsgHdr_ST	Msg;
		u32				Data[3];
	} Msg;

	Msg.Msg.msgSrcId  = DVBT_BDA_CONTROL_MSG_ID;
	Msg.Msg.msgDstId  = HIF_TASK;
	Msg.Msg.msgFlags  = 0;
	Msg.Msg.msgType   = MSG_SMS_RF_TUNE_REQ;
	Msg.Msg.msgLength = sizeof(Msg);
	Msg.Data[0] = fep->frequency;
	Msg.Data[2] = 12000000;

	printk("%s freq %d band %d\n", __FUNCTION__, fep->frequency, fep->u.ofdm.bandwidth);

	switch(fep->u.ofdm.bandwidth)
	{
		case BANDWIDTH_8_MHZ: Msg.Data[1] = BW_8_MHZ; break;
		case BANDWIDTH_7_MHZ: Msg.Data[1] = BW_7_MHZ; break;
		case BANDWIDTH_6_MHZ: Msg.Data[1] = BW_6_MHZ; break;
//		case BANDWIDTH_5_MHZ: Msg.Data[1] = BW_5_MHZ; break;
		case BANDWIDTH_AUTO: return -EOPNOTSUPP;
		default: return -EINVAL;
	}

	return smsdvb_sendrequest_and_wait(client, &Msg, sizeof(Msg), &client->tune_done);
}

static int smsdvb_get_frontend(struct dvb_frontend *fe, struct dvb_frontend_parameters *fep)
{
	smsdvb_client_t *client = container_of(fe, smsdvb_client_t, frontend);

	printk("%s\n", __FUNCTION__);

	// todo:
	memcpy(fep, &client->fe_params, sizeof(struct dvb_frontend_parameters));
	return 0;
}

static void smsdvb_release(struct dvb_frontend *fe)
{
	// do nothing
}

static struct dvb_frontend_ops smsdvb_fe_ops = {
	.info = {
		.name				= "Siano Mobile Digital SMS10xx",
		.type				= FE_OFDM,
		.frequency_min		= 44250000,
		.frequency_max		= 867250000,
		.frequency_stepsize	= 250000,
		.caps = FE_CAN_INVERSION_AUTO |
				FE_CAN_FEC_1_2 | FE_CAN_FEC_2_3 | FE_CAN_FEC_3_4 |
				FE_CAN_FEC_5_6 | FE_CAN_FEC_7_8 | FE_CAN_FEC_AUTO |
				FE_CAN_QPSK | FE_CAN_QAM_16 | FE_CAN_QAM_64 | FE_CAN_QAM_AUTO |
				FE_CAN_TRANSMISSION_MODE_AUTO |
				FE_CAN_GUARD_INTERVAL_AUTO |
				FE_CAN_RECOVER |
				FE_CAN_HIERARCHY_AUTO,
	},

	.release = smsdvb_release,

	.set_frontend = smsdvb_set_frontend,
	.get_frontend = smsdvb_get_frontend,
	.get_tune_settings = smsdvb_get_tune_settings,

	.read_status = smsdvb_read_status,
	.read_ber = smsdvb_read_ber,
	.read_signal_strength = smsdvb_read_signal_strength,
	.read_snr = smsdvb_read_snr,
};

int smsdvb_hotplug(smscore_device_t *coredev, struct device* device, int arrival)
{
	smsclient_params_t params;
	smsdvb_client_t* client;
	int rc;

	// device removal handled by onremove callback
	if (!arrival)
		return 0;

	if (smscore_get_device_mode(coredev) != 4)
	{
		rc = smscore_set_device_mode(coredev, 4);
		if (rc < 0)
			return rc;
	}

	client = kzalloc(sizeof(smsdvb_client_t), GFP_KERNEL);
	if (!client)
	{
		printk(KERN_INFO "%s kmalloc() failed\n", __FUNCTION__);
		return -ENOMEM;
	}

	// register dvb adapter
	rc = dvb_register_adapter(&client->adapter, "Siano Digital Receiver", THIS_MODULE, device, adapter_nr);
	if (rc < 0)
	{
		printk("%s dvb_register_adapter() failed %d\n", __func__, rc);
		goto adapter_error;
	}

	// init dvb demux
	client->demux.dmx.capabilities = DMX_TS_FILTERING;
	client->demux.filternum = 32; // todo: nova ???
	client->demux.feednum = 32;
	client->demux.start_feed = smsdvb_start_feed;
	client->demux.stop_feed = smsdvb_stop_feed;

	rc = dvb_dmx_init(&client->demux);
	if (rc < 0)
	{
		printk("%s dvb_dmx_init failed %d\n\n", __FUNCTION__, rc);
		goto dvbdmx_error;
	}

	// init dmxdev
	client->dmxdev.filternum = 32;
	client->dmxdev.demux = &client->demux.dmx;
	client->dmxdev.capabilities = 0;

	rc = dvb_dmxdev_init(&client->dmxdev, &client->adapter);
	if (rc < 0)
	{
		printk("%s dvb_dmxdev_init failed %d\n", __FUNCTION__, rc);
		goto dmxdev_error;
	}

	// init and register frontend
	memcpy(&client->frontend.ops, &smsdvb_fe_ops, sizeof(struct dvb_frontend_ops));

	rc = dvb_register_frontend(&client->adapter, &client->frontend);
	if (rc < 0)
	{
		printk("%s frontend registration failed %d\n", __FUNCTION__, rc);
		goto frontend_error;
	}

	params.initial_id = 0;
	params.data_type = MSG_SMS_DVBT_BDA_DATA;
	params.onresponse_handler = smsdvb_onresponse;
	params.onremove_handler = smsdvb_onremove;
	params.context = client;

	rc = smscore_register_client(coredev, &params, &client->smsclient);
	if (rc < 0)
	{
		printk(KERN_INFO "%s smscore_register_client() failed %d\n", __FUNCTION__, rc);
		goto client_error;
	}

	client->coredev = coredev;

	init_completion(&client->tune_done);
	init_completion(&client->stat_done);

	kmutex_lock(&g_smsdvb_clientslock);

	list_add(&client->entry, &g_smsdvb_clients);

	kmutex_unlock(&g_smsdvb_clientslock);

	printk(KERN_INFO "%s success\n", __FUNCTION__);

	return 0;

client_error:
	dvb_unregister_frontend(&client->frontend);

frontend_error:
	dvb_dmxdev_release(&client->dmxdev);

dmxdev_error:
	dvb_dmx_release(&client->demux);

dvbdmx_error:
	dvb_unregister_adapter(&client->adapter);

adapter_error:
	kfree(client);
	return rc;
}

int smsdvb_module_init(void)
{
	int rc;

	INIT_LIST_HEAD(&g_smsdvb_clients);
	kmutex_init(&g_smsdvb_clientslock);

	rc = smscore_register_hotplug(smsdvb_hotplug);

	printk(KERN_INFO "%s, rc %d\n", __FUNCTION__, rc);

	return rc;
}

void smsdvb_module_exit(void)
{
	smscore_unregister_hotplug(smsdvb_hotplug);

	kmutex_lock(&g_smsdvb_clientslock);

	while (!list_empty(&g_smsdvb_clients))
		smsdvb_unregister_client((smsdvb_client_t*) g_smsdvb_clients.next);

	kmutex_unlock(&g_smsdvb_clientslock);

	printk(KERN_INFO "%s\n", __FUNCTION__);
}

module_init(smsdvb_module_init);
module_exit(smsdvb_module_exit);

MODULE_DESCRIPTION("smsdvb dvb-api module");
MODULE_AUTHOR("Anatoly Greenblatt,,, (anatolyg@siano-ms.com)");
MODULE_LICENSE("GPL");

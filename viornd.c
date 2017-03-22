/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2017 James S Blachly, MD <james.blachly@gmail.com
 * based on usr/src/uts/common/crypto/io/swrand.c
 */

/*
 * References:
 * 
 * https://ozlabs.org/~rusty/virtio-spec/virtio-0.9.5.pdf
 * http://docs.oasis-open.org/virtio/virtio/v1.0/virtio-v1.0.html
 *
 * http://src.illumos.org/source/xref/illumos-gate/usr/src/uts/common/crypto/io/dca.c
 *
 * https://blogs.oracle.com/darren/entry/solaris_random_number_generation
 */

#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/sysmacros.h>		/* container_of */
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/modctl.h>
#include <sys/crypto/spi.h>

#include "virtiovar.h"
#include "virtioreg.h"

/*
 * Treatise on not blindly depleting host entropy here
 *
 * As best as I can tell:
 * FreeBSD: 20 bytes/sec (is this right? 1 byte enqueued * 5hz)
 * OpenBSD: 16 bytes/8 min. (default)
 * NetBSD : 32 byte buf; viornd_get is a callback from elsewhere in kernel (entropy on demand?)
 */

#define VIORND_FEATURES	0				/* No features	*/
#define	VIORND_BUFSIZE	16				/* Bytes		*/
#define VIORND_INTERVAL	60				/* Seconds		*/

struct viornd_softc {
	dev_info_t			*sc_dev;		/* mirrors virtio_softc->sc_dev */
	struct virtio_softc	sc_virtio;		/* parent */

	struct virtqueue	*sc_vq;
	int					*sc_buf;
	
	/*
	//bd_handle_t		bd_h;
	struct vioblk_req	*sc_reqs;
	struct vioblk_stats	*ks_data;
	kstat_t			*sc_intrstat;
	uint64_t		sc_capacity;
	uint64_t		sc_nblks;
	struct vioblk_lstats	sc_stats;
	short			sc_blkflags;
	boolean_t		sc_in_poll_mode;
	boolean_t		sc_readonly;
	int			sc_blk_size;
	int			sc_pblk_size;
	int			sc_seg_max;
	int			sc_seg_size_max;
	*/
	clock_t			sc_ticks;			/* Cycles/clock ticks */
	timeout_id_t	sc_timeout_id;

	kmutex_t		lock_devid;
	kcondvar_t		cv_devid;
	//char			devid[VIRTIO_BLK_ID_BYTES + 1];
};

uint_t	viornd_read_entropy(caddr_t arg1, caddr_t arg2);
void	viornd_request_entropy(void *arg);

static crypto_kcf_provider_handle_t viornd_prov_handle = NULL;

static char viornd_ident[] = "VirtIO Entropy Provider";

static int viornd_attach(dev_info_t *, ddi_attach_cmd_t);
static int viornd_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops viornd_ops = {
	.devo_rev		= DEVO_REV,
	.devo_getinfo	= ddi_no_info,
	.devo_identify	= nulldev,
	.devo_probe		= nulldev,
	.devo_attach	= viornd_attach,
	.devo_detach	= viornd_detach,
	.devo_reset		= nodev,
	.devo_quiesce	= nulldev
};

 /*
 * Module linkage information for the kernel.
 */

/* from: sys/modctl.h */
extern struct mod_ops mod_driverops;
extern struct mod_ops mod_cryptoops;

static struct modldrv modldrv = {
	 &mod_driverops,				// type of module (driver)
	 viornd_ident,					/* NB: Shown by `modlist` */
	 &viornd_ops					// Driver operations
 };

static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	viornd_ident					/* NB: shown by `modlist` */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	(void *)&modlcrypto,
	NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */
static void viornd_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t viornd_control_ops = {
	viornd_provider_status
};

static int viornd_seed_random(crypto_provider_handle_t, crypto_session_id_t,
    uchar_t *, size_t, uint_t, uint32_t, crypto_req_handle_t);
static int viornd_generate_random(crypto_provider_handle_t,
    crypto_session_id_t, uchar_t *, size_t, crypto_req_handle_t);

static crypto_random_number_ops_t viornd_random_number_ops = {
	viornd_seed_random,
	viornd_generate_random
};

static crypto_ops_t viornd_crypto_ops = {
    .co_control_ops	= &viornd_control_ops,
	.co_random_ops = &viornd_random_number_ops
};

/*
typedef struct crypto_mech_info {
	crypto_mech_name_t	cm_mech_name;
	crypto_mech_type_t	cm_mech_number;
	crypto_func_group_t	cm_func_group_mask;
	ssize_t			cm_min_key_length;
	ssize_t			cm_max_key_length;
	uint32_t		cm_mech_flags;
} crypto_mech_info_t;
*/
#define	CRYPTO_FG_RANDOM	0x80000000	/* generate_random() */
static crypto_mech_info_t viornd_mech_info = {
	"virtio_rand_mech", 0, CRYPTO_FG_RANDOM, 0, 0, 0
};

/* CRYPTO_SW_PROVIDER needs to assign {&modlinkage} to .pi_provider_dev */
static crypto_provider_info_t viornd_prov_info = {
	.pi_interface_version 	= CRYPTO_SPI_VERSION_4,
	.pi_provider_description = "viornd/0 Virtio Entropy Source",	// For KCF, not shown in modlist, max 32ch
	.pi_provider_type 		= CRYPTO_HW_PROVIDER,					// Need testing ; worked as SW_PROVIDER w caveats
	.pi_ops_vector 			= &viornd_crypto_ops,
	.pi_mech_list_count 	= 1,
	.pi_mechanisms 			= &viornd_mech_info
};

/*
 * device driver ops
 */
static int
viornd_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd) {
	int ret, instance;
	struct viornd_softc *sc;
	struct virtio_softc *vsc;

	instance = ddi_get_instance(devinfo);

	switch (cmd) {
		case DDI_ATTACH:
			break;
		case DDI_RESUME:
		case DDI_PM_RESUME:
			dev_err(devinfo, CE_WARN, "Suspend/resume not supported for viornd");
			return DDI_FAILURE;
		default:
			dev_err(devinfo, CE_WARN, "Unrecognized cmd 0x%x", cmd);
			return DDI_FAILURE;
	}

	sc = kmem_zalloc(sizeof (struct viornd_softc), KM_SLEEP);
	ddi_set_driver_private(devinfo, sc);

	vsc = &sc->sc_virtio;

	sc->sc_dev = devinfo;
	vsc->sc_dev = devinfo;


	// virtio_device_reset(vsc)
	// virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	// virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	// Negotiate Features
	(void) virtio_negotiate_features(vsc, VIORND_FEATURES);

	// Set callback frequency (how often to harvest entropy from host)
	sc->sc_ticks = drv_usectohz(VIORND_INTERVAL * 1000000);

	// Allocate DMA buffer

	// Allocate the virtqueue
	sc->sc_vq = virtio_alloc_vq(vsc, 0, VIORND_BUFSIZE, 1, "Entropy request");
	if (!sc->sc_vq) {
		// free allocated DMA buffer
		virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_FAILED);
		// free any kstats
		// free any kmem
		return DDI_FAILURE;
	}

	// Register with the KCF
	// TODO: make function call
	viornd_prov_info.pi_provider_dev.pd_hw = devinfo;
	viornd_prov_info.pi_provider_handle	   = sc;
	if ((ret = crypto_register_provider(&viornd_prov_info, &viornd_prov_handle)) != 0) {
		cmn_err(CE_WARN, "viornd attach(): crypto_register_provider failed");
		/*(void) mod_remove(&modlinkage);
		ret = EACCES;
		goto exit2;	// physmem_ent_fini(&entsrc); return ret;
		*/
		return DDI_FAILURE;
	}

	// Set driver status to OK
	virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER_OK);

	// Set interrupt handler
	struct virtio_int_handler viornd_vq_h = {
		viornd_read_entropy
	};
	ret = virtio_register_ints(vsc, NULL, &viornd_vq_h);
	if (ret) {
		dev_err(devinfo, CE_WARN, "Failed to register interrupts");
		// free allocated DMA buffer
		virtio_set_status(vsc, VIRTIO_CONFIG_DEVICE_STATUS_FAILED);
		// free any kstats
		// free any kmem
		return DDI_FAILURE;
	}

	// start interrupts
	virtio_start_vq_intr(sc->sc_vq);
	ret = virtio_enable_ints(vsc);
	if (ret) {
		virtio_stop_vq_intr(sc->sc_vq);
		// all other stuff
		return DDI_FAILURE;
	}


	return DDI_SUCCESS;

}

static int
viornd_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd) {
	struct viornd_softc *sc = ddi_get_driver_private(devinfo);

	switch (cmd) {
		case DDI_DETACH:
			break;
		case DDI_PM_SUSPEND:
			dev_err(devinfo, CE_WARN, "Suspend/resume not supported for viornd");
			return DDI_FAILURE;
		default:
			dev_err(devinfo, CE_WARN, "Unrecognized cmd 0x%x", cmd);
			return DDI_FAILURE;
	}

	// stop virtqueue interrupts
	virtio_stop_vq_intr(sc->sc_vq);

	// release interrupts
	virtio_release_ints(&sc->sc_virtio);

	// free memory?


	// free the virtqueue
	virtio_free_vq(sc->sc_vq);

	// ???

	return DDI_SUCCESS;
}

/*
 * kmod entry points
 */
int
_init(void)
{
	int ret;

	cmn_err(CE_WARN, "viornd _init()");
	// 1. initialize entropy pool

	// 2. register module
	if ((ret = mod_install(&modlinkage)) != DDI_SUCCESS)
		goto exit2;
	
	// 3. (Swrand) schedule periodic mixing of the pool (query viornd?)

	/* 4. Register with KCF. If the registration fails, return error. */
	// This was moved to attach()

	return (0);

exit2:
	return ret;
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int rv;

	cmn_err(CE_WARN, "viornd _fini");
	// Unregister from the Kernel Crypto Framework;
	// TODO: Move this to detach()?
	if (viornd_prov_handle != NULL) {
		if (crypto_unregister_provider(viornd_prov_handle))
			return EBUSY;
		
		viornd_prov_handle = NULL;
	}

	if ((rv = mod_remove(&modlinkage)) == DDI_SUCCESS) {
		// ???
	}

	return rv;
}

/*
 * KCF Control entry points.
 */
/* ARGSUSED */
static void
viornd_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * KCF Random number entry points.
 */
/* ARGSUSED */
static int
viornd_seed_random(crypto_provider_handle_t provider, crypto_session_id_t sid,
    uchar_t *buf, size_t len, uint_t entropy_est, uint32_t flags,
    crypto_req_handle_t req)
{
	/* The entropy estimate is always 0 in this path */
	/*
		if (flags & CRYPTO_SEED_NOW)
			swrand_add_entropy(buf, len, 0);
		else
			swrand_add_entropy_later(buf, len);
	*/
	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
viornd_generate_random(crypto_provider_handle_t provider,
    crypto_session_id_t sid, uchar_t *buf, size_t len, crypto_req_handle_t req)
{
	/*
		if (crypto_kmflag(req) == KM_NOSLEEP)
			(void) swrand_get_entropy(buf, len, B_TRUE);
		else
			(void) swrand_get_entropy(buf, len, B_FALSE);
	*/
	return (CRYPTO_SUCCESS);
}


/* Interrupt handler */
uint_t
viornd_read_entropy(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *vsc = (void *)arg1;
	struct viornd_softc *sc = container_of(vsc, struct viornd_softc, sc_virtio);

	cmn_err(CE_WARN, "viornd_read_entropy");

	/* Read DMA buffer */
	// ...

	// ret = random_add_entropy((uint8_t *ptr) buf, len, entropy_est);	/* KCF function */

	/* Schedule next entropy request */
	sc->sc_timeout_id = timeout(viornd_request_entropy, sc, sc->sc_ticks);

	return DDI_INTR_CLAIMED;	// success
}

/* Scheduled callback fn */
void
viornd_request_entropy(void *arg)
{
	cmn_err(CE_WARN, "viornd_request_entropy");

	/* enqueue a request for entropy */
	// ...
}
#
# $FreeBSD$
#

PROG=	bhyve

SRCS=	atpic.c consport.c dbgport.c elcr.c fbsdrun.c inout.c mevent.c
SRCS+=	pci_emul.c pci_hostbridge.c pci_passthru.c pci_virtio_block.c
SRCS+=	pci_virtio_net.c pit_8254.c post.c rtc.c uart.c xmsr.c

NO_MAN=

DPADD=	${LIBVMMAPI} ${LIBMD} ${LIBPTHREAD}
LDADD=	-lvmmapi -lmd -lpthread

WARNS?=	2

CFLAGS+= -I${.CURDIR}/../../sys

.include <bsd.prog.mk>

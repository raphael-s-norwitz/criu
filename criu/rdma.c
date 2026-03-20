#include <stdio.h>

#include "common/compiler.h"
#include "imgset.h"
#include "image.h"
#include "files.h"
#include "files-reg.h"
#include "int.h"
#include "log.h"
#include "protobuf.h"
#include "rdma.h"
#include "fdinfo.h"

#include "images/fdinfo.pb-c.h"
#include "images/uverbsfd.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "rdma: "

static int dump_uverbsfile(int lfd, u32 id, const struct fd_parms *p)
{
	UverbsFileEntry uve = UVERBS_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;
	struct cr_img *img;

	uve.id = id;

	if (parse_fdinfo_pid(p->pid, p->fd, FD_TYPES__UVERBSFD, &uve))
		return -1;

	if (dump_one_reg_file(lfd, id, p))
		return -1;

	pr_info("Dumping uverbs char device %d with id %#x", lfd, id);
	if (uve.has_ctxn)
		pr_info(" ctxn %u", uve.ctxn);
	pr_info("\n");

	/* IB dev name, etc. */

	fe.type = FD_TYPES__UVERBSFD;
	fe.id = uve.id;
	fe.uvfd = &uve;

	img = img_from_set(glob_imgset, CR_FD_FILES);
	return pb_write_one(img, &fe, PB_FILE);
}

const struct fdtype_ops uverbs_dump_ops = {
	.type = FD_TYPES__UVERBSFD,
	.dump = dump_uverbsfile,
};

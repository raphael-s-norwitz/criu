#ifndef __CR_RDMA_H__
#define __CR_RDMA_H__

extern const struct fdtype_ops uverbs_dump_ops;
extern const struct fdtype_ops uverbs_async_eventfd_dump_ops;

bool is_async_eventfd(char *link);

#endif /* __CR_RDMA_H__ */

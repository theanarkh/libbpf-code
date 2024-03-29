/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED! */
#ifndef __HELLO_BPF_SKEL_H__
#define __HELLO_BPF_SKEL_H__

#include <stdlib.h>
#include <bpf/libbpf.h>

struct hello_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_program *handle_tp;
	} progs;
	struct {
		struct bpf_link *handle_tp;
	} links;
};

static void
hello_bpf__destroy(struct hello_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
hello_bpf__create_skeleton(struct hello_bpf *obj);

static inline struct hello_bpf *
hello_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct hello_bpf *obj;

	obj = (struct hello_bpf *)calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;
	if (hello_bpf__create_skeleton(obj))
		goto err;
	if (bpf_object__open_skeleton(obj->skeleton, opts))
		goto err;

	return obj;
err:
	hello_bpf__destroy(obj);
	return NULL;
}

static inline struct hello_bpf *
hello_bpf__open(void)
{
	return hello_bpf__open_opts(NULL);
}

static inline int
hello_bpf__load(struct hello_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct hello_bpf *
hello_bpf__open_and_load(void)
{
	struct hello_bpf *obj;

	obj = hello_bpf__open();
	if (!obj)
		return NULL;
	if (hello_bpf__load(obj)) {
		hello_bpf__destroy(obj);
		return NULL;
	}
	return obj;
}

static inline int
hello_bpf__attach(struct hello_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
hello_bpf__detach(struct hello_bpf *obj)
{
	return bpf_object__detach_skeleton(obj->skeleton);
}

static inline int
hello_bpf__create_skeleton(struct hello_bpf *obj)
{
	struct bpf_object_skeleton *s;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)
		return -1;
	obj->skeleton = s;

	s->sz = sizeof(*s);
	s->name = "hello_bpf";
	s->obj = &obj->obj;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs)
		goto err;

	s->progs[0].name = "handle_tp";
	s->progs[0].prog = &obj->progs.handle_tp;
	s->progs[0].link = &obj->links.handle_tp;

	s->data_sz = 2040;
	s->data = (void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\xf8\x04\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0c\0\
\x0b\0\x85\0\0\0\x0e\0\0\0\xb7\x01\0\0\x64\x2e\x0a\0\x63\x1a\xf8\xff\0\0\0\0\
\x18\x01\0\0\x6f\x6d\x20\x50\0\0\0\0\x49\x44\x20\x25\x7b\x1a\xf0\xff\0\0\0\0\
\x18\x01\0\0\x67\x65\x72\x65\0\0\0\0\x64\x20\x66\x72\x7b\x1a\xe8\xff\0\0\0\0\
\x18\x01\0\0\x42\x50\x46\x20\0\0\0\0\x74\x72\x69\x67\x7b\x1a\xe0\xff\0\0\0\0\
\x77\0\0\0\x20\0\0\0\xbf\xa1\0\0\0\0\0\0\x07\x01\0\0\xe0\xff\xff\xff\xb7\x02\0\
\0\x1c\0\0\0\xbf\x03\0\0\0\0\0\0\x85\0\0\0\x06\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\
\0\0\0\0\0\x42\x50\x46\x20\x74\x72\x69\x67\x67\x65\x72\x65\x64\x20\x66\x72\x6f\
\x6d\x20\x50\x49\x44\x20\x25\x64\x2e\x0a\0\x44\x75\x61\x6c\x20\x42\x53\x44\x2f\
\x47\x50\x4c\0\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x9c\0\0\0\x9c\0\0\0\x27\x01\0\0\
\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\0\0\x01\0\0\x0d\x03\0\0\0\x01\0\0\0\x01\0\0\0\
\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\x09\0\0\0\x01\0\0\x0c\x02\0\0\0\xfe\
\0\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x05\0\0\0\x07\
\0\0\0\x0d\0\0\0\x03\x01\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\x17\x01\0\0\0\0\0\
\x0e\x06\0\0\0\x01\0\0\0\x1f\x01\0\0\x01\0\0\x0f\0\0\0\0\x08\0\0\0\0\0\0\0\x0d\
\0\0\0\0\x63\x74\x78\0\x69\x6e\x74\0\x68\x61\x6e\x64\x6c\x65\x5f\x74\x70\0\x74\
\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x2f\x73\x79\x73\x63\x61\x6c\x6c\x73\x2f\
\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x65\x78\x65\x63\x76\x65\0\x2f\x68\x6f\
\x6d\x65\x2f\x63\x79\x62\x2f\x63\x6f\x64\x65\x2f\x6c\x69\x62\x62\x70\x66\x2d\
\x63\x6f\x64\x65\x2f\x73\x72\x63\x2f\x68\x65\x6c\x6c\x6f\x2e\x62\x70\x66\x2e\
\x63\0\x20\x20\x20\x20\x69\x6e\x74\x20\x70\x69\x64\x20\x3d\x20\x62\x70\x66\x5f\
\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x70\x69\x64\x5f\x74\x67\x69\
\x64\x28\x29\x3e\x3e\x20\x33\x32\x3b\0\x20\x20\x20\x20\x63\x68\x61\x72\x20\x66\
\x6d\x74\x5b\x5d\x20\x3d\x20\x22\x42\x50\x46\x20\x74\x72\x69\x67\x67\x65\x72\
\x65\x64\x20\x66\x72\x6f\x6d\x20\x50\x49\x44\x20\x25\x64\x2e\x5c\x6e\x22\x3b\0\
\x20\x20\x20\x20\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\x69\x6e\x74\
\x6b\x28\x66\x6d\x74\x2c\x20\x73\x69\x7a\x65\x6f\x66\x28\x66\x6d\x74\x29\x2c\
\x20\x70\x69\x64\x29\x3b\0\x20\x20\x20\x20\x72\x65\x74\x75\x72\x6e\x20\x30\x3b\
\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\
\x59\x50\x45\x5f\x5f\0\x4c\x49\x43\x45\x4e\x53\x45\0\x6c\x69\x63\x65\x6e\x73\
\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x14\0\0\0\x14\0\0\0\x6c\0\0\0\x80\0\0\0\
\0\0\0\0\x08\0\0\0\x13\0\0\0\x01\0\0\0\0\0\0\0\x04\0\0\0\x10\0\0\0\x13\0\0\0\
\x06\0\0\0\0\0\0\0\x38\0\0\0\x63\0\0\0\x0f\x1c\0\0\x10\0\0\0\x38\0\0\0\x92\0\0\
\0\x0a\x20\0\0\x60\0\0\0\x38\0\0\0\x63\0\0\0\x29\x1c\0\0\x70\0\0\0\x38\0\0\0\0\
\0\0\0\0\0\0\0\x78\0\0\0\x38\0\0\0\xc3\0\0\0\x05\x24\0\0\x90\0\0\0\x38\0\0\0\
\xf0\0\0\0\x05\x28\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x03\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x72\0\0\0\x11\0\x04\0\0\0\
\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x14\0\0\0\x12\0\x02\0\0\0\0\0\0\0\0\0\xa0\0\0\0\
\0\0\0\0\xac\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\x2c\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\
\0\x40\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x50\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x60\
\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x70\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x80\0\0\0\
\0\0\0\0\0\0\0\0\x01\0\0\0\x90\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x09\x08\0\x2e\
\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x68\x61\
\x6e\x64\x6c\x65\x5f\x74\x70\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\
\x67\0\x74\x72\x61\x63\x65\x70\x6f\x69\x6e\x74\x2f\x73\x79\x73\x63\x61\x6c\x6c\
\x73\x2f\x73\x79\x73\x5f\x65\x6e\x74\x65\x72\x5f\x65\x78\x65\x63\x76\x65\0\x6c\
\x69\x63\x65\x6e\x73\x65\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\
\x61\x62\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\x2e\
\x72\x6f\x64\x61\x74\x61\x2e\x73\x74\x72\x31\x2e\x31\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x2c\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\
\0\0\0\0\0\0\xa0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x7a\0\0\0\x01\0\0\0\x32\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe0\0\0\0\0\0\0\0\x1c\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x51\0\0\0\
\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xfc\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6d\0\0\0\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x09\x01\0\0\0\0\0\0\xdb\x01\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xe4\x02\0\0\0\0\0\0\xa0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x61\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x88\
\x03\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x0b\0\0\0\x02\0\0\0\x08\0\0\0\0\0\0\0\x18\0\
\0\0\0\0\0\0\x69\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe8\x03\0\0\0\
\0\0\0\x10\0\0\0\0\0\0\0\x07\0\0\0\x05\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\
\0\x07\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf8\x03\0\0\0\0\0\0\x70\
\0\0\0\0\0\0\0\x07\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x1e\0\0\
\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\x68\x04\0\0\0\0\0\0\x02\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x59\0\0\0\x03\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6a\x04\0\0\0\0\0\0\x89\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return -1;
}

#endif /* __HELLO_BPF_SKEL_H__ */

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED! */
#ifndef __UPROBE_BPF_SKEL_H__
#define __UPROBE_BPF_SKEL_H__

#include <stdlib.h>
#include <bpf/libbpf.h>

struct uprobe_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *uprobe;
		struct bpf_program *uretprobe;
	} progs;
	struct {
		struct bpf_link *uprobe;
		struct bpf_link *uretprobe;
	} links;
	struct uprobe_bpf__rodata {
		char ____uprobe_____fmt[23];
		char ____uretprobe_____fmt[21];
	} *rodata;
};

static void
uprobe_bpf__destroy(struct uprobe_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
uprobe_bpf__create_skeleton(struct uprobe_bpf *obj);

static inline struct uprobe_bpf *
uprobe_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct uprobe_bpf *obj;

	obj = (struct uprobe_bpf *)calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;
	if (uprobe_bpf__create_skeleton(obj))
		goto err;
	if (bpf_object__open_skeleton(obj->skeleton, opts))
		goto err;

	return obj;
err:
	uprobe_bpf__destroy(obj);
	return NULL;
}

static inline struct uprobe_bpf *
uprobe_bpf__open(void)
{
	return uprobe_bpf__open_opts(NULL);
}

static inline int
uprobe_bpf__load(struct uprobe_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct uprobe_bpf *
uprobe_bpf__open_and_load(void)
{
	struct uprobe_bpf *obj;

	obj = uprobe_bpf__open();
	if (!obj)
		return NULL;
	if (uprobe_bpf__load(obj)) {
		uprobe_bpf__destroy(obj);
		return NULL;
	}
	return obj;
}

static inline int
uprobe_bpf__attach(struct uprobe_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
uprobe_bpf__detach(struct uprobe_bpf *obj)
{
	return bpf_object__detach_skeleton(obj->skeleton);
}

static inline int
uprobe_bpf__create_skeleton(struct uprobe_bpf *obj)
{
	struct bpf_object_skeleton *s;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)
		return -1;
	obj->skeleton = s;

	s->sz = sizeof(*s);
	s->name = "uprobe_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 1;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps)
		goto err;

	s->maps[0].name = "uprobe_b.rodata";
	s->maps[0].map = &obj->maps.rodata;
	s->maps[0].mmaped = (void **)&obj->rodata;

	/* programs */
	s->prog_cnt = 2;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs)
		goto err;

	s->progs[0].name = "uprobe";
	s->progs[0].prog = &obj->progs.uprobe;
	s->progs[0].link = &obj->links.uprobe;

	s->progs[1].name = "uretprobe";
	s->progs[1].prog = &obj->progs.uretprobe;
	s->progs[1].link = &obj->links.uretprobe;

	s->data_sz = 3008;
	s->data = (void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0f\0\x0e\
\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x17\0\0\0\x85\0\0\0\x06\0\0\
\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\x18\x01\0\0\x17\0\0\0\0\0\0\0\0\0\0\0\
\xb7\x02\0\0\x15\0\0\0\x85\0\0\0\x06\0\0\0\xb7\0\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\
\x44\x75\x61\x6c\x20\x42\x53\x44\x2f\x47\x50\x4c\0\x52\x75\x6e\x42\x6f\x6f\x74\
\x73\x74\x72\x61\x70\x70\x69\x6e\x67\x20\x73\x74\x61\x72\x74\0\x52\x75\x6e\x42\
\x6f\x6f\x74\x73\x74\x72\x61\x70\x70\x69\x6e\x67\x20\x65\x6e\x64\0\x9f\xeb\x01\
\0\x18\0\0\0\0\0\0\0\x54\x02\0\0\x54\x02\0\0\xc5\x01\0\0\0\0\0\0\0\0\0\x02\x02\
\0\0\0\x01\0\0\0\x15\0\0\x04\xa8\0\0\0\x09\0\0\0\x03\0\0\0\0\0\0\0\x0d\0\0\0\
\x03\0\0\0\x40\0\0\0\x11\0\0\0\x03\0\0\0\x80\0\0\0\x15\0\0\0\x03\0\0\0\xc0\0\0\
\0\x19\0\0\0\x03\0\0\0\0\x01\0\0\x1d\0\0\0\x03\0\0\0\x40\x01\0\0\x21\0\0\0\x03\
\0\0\0\x80\x01\0\0\x25\0\0\0\x03\0\0\0\xc0\x01\0\0\x29\0\0\0\x03\0\0\0\0\x02\0\
\0\x2c\0\0\0\x03\0\0\0\x40\x02\0\0\x2f\0\0\0\x03\0\0\0\x80\x02\0\0\x33\0\0\0\
\x03\0\0\0\xc0\x02\0\0\x37\0\0\0\x03\0\0\0\0\x03\0\0\x3b\0\0\0\x03\0\0\0\x40\
\x03\0\0\x3f\0\0\0\x03\0\0\0\x80\x03\0\0\x43\0\0\0\x03\0\0\0\xc0\x03\0\0\x4c\0\
\0\0\x03\0\0\0\0\x04\0\0\x50\0\0\0\x03\0\0\0\x40\x04\0\0\x53\0\0\0\x03\0\0\0\
\x80\x04\0\0\x5a\0\0\0\x03\0\0\0\xc0\x04\0\0\x5e\0\0\0\x03\0\0\0\0\x05\0\0\x61\
\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\0\0\0\0\x01\0\0\x0d\x05\0\0\0\x73\0\0\0\
\x01\0\0\0\x77\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\x7b\0\0\0\x01\0\0\x0c\x04\
\0\0\0\0\0\0\0\x01\0\0\x0d\x05\0\0\0\x73\0\0\0\x01\0\0\0\x04\x01\0\0\x01\0\0\
\x0c\x07\0\0\0\x6b\x01\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\
\0\0\0\x09\0\0\0\x0b\0\0\0\x0d\0\0\0\x70\x01\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\
\x84\x01\0\0\0\0\0\x0e\x0a\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x0a\x09\0\0\0\0\0\0\0\
\0\0\0\x03\0\0\0\0\x0d\0\0\0\x0b\0\0\0\x17\0\0\0\x8c\x01\0\0\0\0\0\x0e\x0e\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x0d\0\0\0\x0b\0\0\0\x15\0\0\0\x9f\x01\0\0\
\0\0\0\x0e\x10\0\0\0\0\0\0\0\xb5\x01\0\0\x02\0\0\x0f\0\0\0\0\x0f\0\0\0\0\0\0\0\
\x17\0\0\0\x11\0\0\0\x17\0\0\0\x15\0\0\0\xbd\x01\0\0\x01\0\0\x0f\0\0\0\0\x0c\0\
\0\0\0\0\0\0\x0d\0\0\0\0\x70\x74\x5f\x72\x65\x67\x73\0\x72\x31\x35\0\x72\x31\
\x34\0\x72\x31\x33\0\x72\x31\x32\0\x72\x62\x70\0\x72\x62\x78\0\x72\x31\x31\0\
\x72\x31\x30\0\x72\x39\0\x72\x38\0\x72\x61\x78\0\x72\x63\x78\0\x72\x64\x78\0\
\x72\x73\x69\0\x72\x64\x69\0\x6f\x72\x69\x67\x5f\x72\x61\x78\0\x72\x69\x70\0\
\x63\x73\0\x65\x66\x6c\x61\x67\x73\0\x72\x73\x70\0\x73\x73\0\x6c\x6f\x6e\x67\
\x20\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x63\x74\x78\0\x69\x6e\
\x74\0\x75\x70\x72\x6f\x62\x65\0\x75\x70\x72\x6f\x62\x65\x2f\x52\x75\x6e\x42\
\x6f\x6f\x74\x73\x74\x72\x61\x70\x70\x69\x6e\x67\0\x2f\x68\x6f\x6d\x65\x2f\x63\
\x79\x62\x2f\x63\x6f\x64\x65\x2f\x6c\x69\x62\x62\x70\x66\x2d\x63\x6f\x64\x65\
\x2f\x73\x72\x63\x2f\x75\x70\x72\x6f\x62\x65\x2e\x62\x70\x66\x2e\x63\0\x09\x62\
\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x52\x75\x6e\x42\x6f\x6f\x74\x73\
\x74\x72\x61\x70\x70\x69\x6e\x67\x20\x73\x74\x61\x72\x74\x22\x29\x3b\0\x69\x6e\
\x74\x20\x42\x50\x46\x5f\x4b\x50\x52\x4f\x42\x45\x28\x75\x70\x72\x6f\x62\x65\
\x29\0\x75\x72\x65\x74\x70\x72\x6f\x62\x65\0\x75\x72\x65\x74\x70\x72\x6f\x62\
\x65\x2f\x52\x75\x6e\x42\x6f\x6f\x74\x73\x74\x72\x61\x70\x70\x69\x6e\x67\0\x09\
\x62\x70\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x52\x75\x6e\x42\x6f\x6f\x74\
\x73\x74\x72\x61\x70\x70\x69\x6e\x67\x20\x65\x6e\x64\x22\x29\x3b\0\x69\x6e\x74\
\x20\x42\x50\x46\x5f\x4b\x52\x45\x54\x50\x52\x4f\x42\x45\x28\x75\x72\x65\x74\
\x70\x72\x6f\x62\x65\x29\0\x63\x68\x61\x72\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\
\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x4c\x49\x43\x45\x4e\x53\x45\0\
\x5f\x5f\x5f\x5f\x75\x70\x72\x6f\x62\x65\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x5f\
\x5f\x5f\x5f\x75\x72\x65\x74\x70\x72\x6f\x62\x65\x2e\x5f\x5f\x5f\x5f\x66\x6d\
\x74\0\x2e\x72\x6f\x64\x61\x74\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\x9f\xeb\x01\
\0\x20\0\0\0\0\0\0\0\x24\0\0\0\x24\0\0\0\x54\0\0\0\x78\0\0\0\0\0\0\0\x08\0\0\0\
\x82\0\0\0\x01\0\0\0\0\0\0\0\x06\0\0\0\x0e\x01\0\0\x01\0\0\0\0\0\0\0\x08\0\0\0\
\x10\0\0\0\x82\0\0\0\x02\0\0\0\0\0\0\0\x9a\0\0\0\xc6\0\0\0\x02\x38\0\0\x20\0\0\
\0\x9a\0\0\0\xed\0\0\0\x05\x30\0\0\x0e\x01\0\0\x02\0\0\0\0\0\0\0\x9a\0\0\0\x29\
\x01\0\0\x02\x54\0\0\x20\0\0\0\x9a\0\0\0\x4e\x01\0\0\x05\x4c\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x14\0\0\0\x01\0\x05\0\0\0\0\0\0\
\0\0\0\x17\0\0\0\0\0\0\0\x27\0\0\0\x01\0\x05\0\x17\0\0\0\0\0\0\0\x15\0\0\0\0\0\
\0\0\0\0\0\0\x03\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\xc0\0\0\0\x11\0\x04\0\0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\x8e\0\0\0\x12\0\
\x02\0\0\0\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x95\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\
\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x05\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\
\0\x05\0\0\0\x40\x02\0\0\0\0\0\0\x0a\0\0\0\x05\0\0\0\x4c\x02\0\0\0\0\0\0\x0a\0\
\0\0\x05\0\0\0\x64\x02\0\0\0\0\0\0\0\0\0\0\x06\0\0\0\x2c\0\0\0\0\0\0\0\0\0\0\0\
\x03\0\0\0\x3c\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x50\0\0\0\0\0\0\0\0\0\0\0\x03\0\
\0\0\x60\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x78\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\
\x88\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x0d\x0e\x0c\x02\x03\0\x2e\x74\x65\x78\x74\
\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\x65\x78\x74\0\x5f\x5f\x5f\x5f\x75\x70\
\x72\x6f\x62\x65\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x5f\x5f\x5f\x5f\x75\x72\x65\
\x74\x70\x72\x6f\x62\x65\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x72\x65\x6c\x75\
\x70\x72\x6f\x62\x65\x2f\x52\x75\x6e\x42\x6f\x6f\x74\x73\x74\x72\x61\x70\x70\
\x69\x6e\x67\0\x2e\x72\x65\x6c\x75\x72\x65\x74\x70\x72\x6f\x62\x65\x2f\x52\x75\
\x6e\x42\x6f\x6f\x74\x73\x74\x72\x61\x70\x70\x69\x6e\x67\0\x2e\x6c\x6c\x76\x6d\
\x5f\x61\x64\x64\x72\x73\x69\x67\0\x6c\x69\x63\x65\x6e\x73\x65\0\x75\x70\x72\
\x6f\x62\x65\0\x75\x72\x65\x74\x70\x72\x6f\x62\x65\0\x2e\x73\x74\x72\x74\x61\
\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\x72\x65\
\x6c\x2e\x42\x54\x46\0\x4c\x49\x43\x45\x4e\x53\x45\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x41\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\
\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x5d\
\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x70\0\0\0\0\0\0\0\x30\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x86\0\0\0\x01\0\0\0\
\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa0\0\0\0\0\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xaf\0\0\0\x01\0\0\0\x02\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\xad\0\0\0\0\0\0\0\x2c\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\xbb\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xd9\0\0\0\0\0\0\0\x31\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x0b\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0a\x05\0\0\0\0\
\0\0\x98\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa7\0\
\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa8\x05\0\0\0\0\0\0\xd8\0\0\0\0\
\0\0\0\x0e\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x3d\0\0\0\x09\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x80\x06\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x08\
\0\0\0\x02\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x59\0\0\0\x09\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x06\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x08\0\0\0\x03\
\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xb7\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\xa0\x06\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x08\0\0\0\x06\0\0\0\x08\
\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x07\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\xd0\x06\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x08\0\0\0\x07\0\0\0\x08\0\0\0\0\0\
\0\0\x10\0\0\0\0\0\0\0\x78\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\
\0\0\x30\x07\0\0\0\0\0\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x9f\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x35\x07\0\0\
\0\0\0\0\xc8\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return -1;
}

#endif /* __UPROBE_BPF_SKEL_H__ */

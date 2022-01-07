// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linux

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func getFilePath(ctx context.Context, fd int32) string {
	t := kernel.TaskFromContext(ctx)

	fdt := t.FDTable()
	if fdt == nil {
		return "[err: no FD table]"
	}
	file, _ := fdt.GetVFS2(fd)
	if file == nil {
		return "[err: requires VFS2]"
	}
	defer file.DecRef(ctx)

	root := vfs.RootFromContext(ctx)
	defer root.DecRef(ctx)

	path, err := t.Kernel().VFS().PathnameWithDeleted(ctx, root, file.VirtualDentry())
	if err != nil {
		return fmt.Sprintf("[err: %v]", err)
	}
	return path
}

func PointOpen(ctx context.Context, _ seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Open{Common: common}
	addr := info.Args[0].Pointer()
	if addr > 0 {
		t := kernel.TaskFromContext(ctx)
		path, err := t.CopyInString(addr, linux.PATH_MAX)
		if err == nil {
			p.Pathname = path
		}
	}
	p.Flags = info.Args[1].Uint()
	p.Mode = uint32(info.Args[2].ModeT())
	p.Exit = seccheck.NewExitMaybe(info)
	return p
}

func PointRead(ctx context.Context, fields seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Read{
		Common: common,
		Fd:     int64(info.Args[0].Int()),
		Count:  uint64(info.Args[2].SizeT()),
	}
	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(ctx, int32(p.Fd))
	}

	p.Exit = seccheck.NewExitMaybe(info)

	return p
}

func PointOpenat(ctx context.Context, fields seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Open{
		Common: common,
		Fd:     int64(info.Args[0].Int()),
		Flags:  info.Args[2].Uint(),
	}

	addr := info.Args[1].Pointer()
	if addr > 0 {
		t := kernel.TaskFromContext(ctx)
		path, err := t.CopyInString(addr, linux.PATH_MAX)
		if err == nil {
			p.Pathname = path
		}
	}
	if p.Flags&linux.O_CREAT != 0 {
		p.Mode = uint32(info.Args[3].ModeT())
	}

	p.Exit = seccheck.NewExitMaybe(info)

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(ctx, int32(p.Fd))
	}

	return p
}

func PointConnect(ctx context.Context, fields seccheck.FieldSet, common *pb.Common, info seccheck.SyscallInfo) proto.Message {
	p := &pb.Connect{
		Common: common,
		Fd:     int64(info.Args[0].Int()),
	}

	addr := info.Args[1].Pointer()
	addrlen := info.Args[2].Uint()
	if addr > 0 {
		t := kernel.TaskFromContext(ctx)
		p.Address = make([]byte, addrlen)
		_, _ = t.CopyInBytes(addr, p.Address)
	}

	p.Exit = seccheck.NewExitMaybe(info)

	if fields.Local.Contains(seccheck.FieldSyscallPath) {
		p.FdPath = getFilePath(ctx, int32(p.Fd))
	}

	return p
}

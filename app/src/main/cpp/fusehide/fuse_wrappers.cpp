// Copyright (C) 2026 XiaoTong6666
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

#include "wrappers.hpp"

namespace fusehide {

extern "C" void RecordMonitorEvent(fuse_req_t req, const char* type, uint64_t parentIno, const char* name);
extern "C" void RecordMonitorEventIno(fuse_req_t req, const char* type, uint64_t ino);
extern "C" void RecordMonitorEventPath(uint32_t uid, const char* type, const char* path);

namespace {

thread_local uint32_t gActiveUid = 0;
thread_local uint32_t gLastPathPolicyUid = 0;
thread_local std::string gLastPathPolicyPath;

class ScopedUid final {
   public:
    explicit ScopedUid(uint32_t uid) : previous_(gActiveUid) {
        gActiveUid = uid;
    }
    ~ScopedUid() {
        gActiveUid = previous_;
    }
   private:
    uint32_t previous_;
};

bool ShouldHideLowerFsCreatePath(std::string_view pathView) {
    const uint32_t uid = gActiveUid != 0 ? gActiveUid : gLastPathPolicyUid;
    return uid != 0 && HiddenPathPolicy::IsTestHiddenUid(uid) &&
           HiddenPathPolicy::IsExactHiddenTargetPath(pathView);
}

bool ShouldHideLowerFsPath(std::string_view pathView) {
    const uint32_t uid = gActiveUid != 0 ? gActiveUid : gLastPathPolicyUid;
    return uid != 0 && HiddenPathPolicy::ShouldHideTestPath(uid, pathView);
}

std::string ReadDirectoryPathFromDir(DIR* dirp) {
    if (dirp == nullptr) {
        return {};
    }
    const int fd = dirfd(dirp);
    if (fd < 0) {
        return {};
    }
    char procPath[64];
    std::snprintf(procPath, sizeof(procPath), "/proc/self/fd/%d", fd);
    char resolved[PATH_MAX];
    const ssize_t len = readlink(procPath, resolved, sizeof(resolved) - 1);
    if (len <= 0) {
        return {};
    }
    resolved[len] = '\0';
    return std::string(resolved, static_cast<size_t>(len));
}

bool IsFirstComponentOfHiddenRelativePath(std::string_view name) {
    if (name.empty() || name.find('/') != std::string_view::npos) {
        return false;
    }
    const auto config = CurrentHideConfig();
    for (const auto& hiddenRelativePath : config->hiddenRelativePaths) {
        std::string normalized = hiddenRelativePath;
        while (!normalized.empty() && normalized.front() == '/') {
            normalized.erase(normalized.begin());
        }
        while (!normalized.empty() && normalized.back() == '/') {
            normalized.pop_back();
        }
        if (normalized.empty()) {
            continue;
        }
        const size_t slash = normalized.find('/');
        const std::string_view first = slash == std::string::npos
                                           ? std::string_view(normalized)
                                           : std::string_view(normalized).substr(0, slash);
        if (first == name) {
            return true;
        }
    }
    return false;
}

void InvalidateFilteredParentChildren(std::string_view parentPath,
                                      const std::vector<FilteredDirentMatch>& removedEntries) {
    if (parentPath.empty() || removedEntries.empty()) {
        return;
    }
    const auto parentIno = LookupTrackedInodeForPath(parentPath);
    if (!parentIno.has_value()) {
        DebugLogPrint(4, "skip filtered child invalidation parent=%s names=%zu reason=no_parent_ino",
                      DebugPreview(parentPath).c_str(), removedEntries.size());
        return;
    }
    for (const auto& entry : removedEntries) {
        RuntimeState::ScheduleSpecificEntryInvalidation(*parentIno, entry.name);
        if (entry.ino != 0) {
            const std::string childPath = HiddenPathPolicy::JoinPathComponent(parentPath, entry.name);
            RememberTrackedPathForInode(entry.ino, childPath);
            if (TrackHiddenSubtreeInode(entry.ino)) {
                DebugLogPrint(4, "track filtered child inode parent=%s child=%s ino=%s",
                              DebugPreview(parentPath).c_str(), DebugPreview(entry.name).c_str(),
                              InodePath(entry.ino).c_str());
            }
            RuntimeState::ScheduleHiddenInodeInvalidation(entry.ino);
        }
    }
    DebugLogPrint(4, "invalidate filtered children parent=%s ino=%s names=%zu",
                  DebugPreview(parentPath).c_str(), InodePath(*parentIno).c_str(),
                  removedEntries.size());
}

}  // namespace

extern "C" void WrappedPfLookup(fuse_req_t req, uint64_t parent, const char* name) {
    RuntimeState::RememberFuseSession(req);
    uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);
    if (name != nullptr && IsConfiguredHiddenRootEntryName(name) && parent != 0) {
        uint64_t expected = 0;
        if (gHiddenRootParentInode.compare_exchange_strong(expected, parent, std::memory_order_relaxed)) {
            DebugLogPrint(4, "record hidden root parent=%s", InodePath(parent).c_str());
        }
    }
    gInPfLookup = true;
    gCurrentLookupParentInode = parent;
    gCurrentLookupName = name != nullptr ? std::string(name) : std::string();
    gTrackRootHiddenLookup = IsHiddenLookupCacheTarget(parent, name);
    gTrackHiddenSubtreeLookup = IsTrackedHiddenSubtreeInode(parent);

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*)>(gOriginalPfLookup);
    if (fn) fn(req, parent, name);
    gCurrentLookupParentInode = 0;
    gCurrentLookupName.clear();
    gInPfLookup = false;
    gTrackHiddenSubtreeLookup = false;
    gTrackRootHiddenLookup = false;
}

DirectoryEntries FilterHiddenDirectoryEntries(uint32_t uid, std::string_view parentPath,
                                              DirectoryEntries entries) {
    if (!HiddenPathPolicy::IsTestHiddenUid(uid) || entries.empty()) {
        return entries;
    }

    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [&](const auto& entry) {
                                     if (!entry) return false;
                                     const std::string& name = entry->d_name;
                                     if (name.empty() || name[0] == '/') return false;
                                     return HiddenPathPolicy::ShouldHideTestPath(
                                         uid, HiddenPathPolicy::JoinPathComponent(parentPath, name));
                                 }),
                  entries.end());
    return entries;
}

DirectoryEntries WrappedGetDirectoryEntries(void* wrapper, uint32_t uid, const std::string& path,
                                            DIR* dirp) {
    auto fn = reinterpret_cast<GetDirectoryEntriesFn>(gOriginalGetDirectoryEntries);
    DirectoryEntries entries = fn ? fn(wrapper, uid, path, dirp) : DirectoryEntries();
    if (gCurrentReaddirReqUnique != 0) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        auto it = gPendingReaddirContexts.find(gCurrentReaddirReqUnique);
        if (it != gPendingReaddirContexts.end()) {
            it->second.path = path;
        }
    }
    return FilterHiddenDirectoryEntries(uid, path, std::move(entries));
}

void WrappedAddDirectoryEntriesFromLowerFs(DIR* dirp, LowerFsDirentFilterFn filter,
                                           DirectoryEntries* entries) {
    auto fn = reinterpret_cast<AddDirectoryEntriesFromLowerFsFn>(gOriginalAddDirectoryEntriesFromLowerFs);
    if (fn == nullptr) return;
    fn(dirp, filter, entries);
    if (entries == nullptr || entries->empty()) return;

    const uint32_t uid = gLastPathPolicyUid;
    if (!HiddenPathPolicy::IsTestHiddenUid(uid)) return;

    std::string parentPath = ReadDirectoryPathFromDir(dirp);
    if (parentPath.empty()) {
        parentPath = gLastPathPolicyPath;
    }
    if (parentPath.empty()) return;

    *entries = FilterHiddenDirectoryEntries(uid, parentPath, std::move(*entries));
}

extern "C" void WrappedPfReaddirPostfilter(fuse_req_t req, uint64_t ino, uint32_t error_in,
                                           off_t off_in, off_t off_out, size_t size_out,
                                           const void* dirents_in, void* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, uint32_t, off_t, off_t, size_t,
                                        const void*, void*)>(gOriginalPfReaddirPostfilter);
    if (fn == nullptr) return;

    gInPfReaddirPostfilter = true;
    gPfReaddirUid = uid;
    gPfReaddirIno = ino;
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    fn(req, ino, error_in, off_in, off_out, size_out, dirents_in, fi);
    gCurrentReaddirReqUnique = 0;
    gPfReaddirIno = 0;
    gPfReaddirUid = 0;
    gInPfReaddirPostfilter = false;
}

extern "C" void WrappedPfLookupPostfilter(fuse_req_t req, uint64_t parent, uint32_t error_in,
                                          const char* name, struct fuse_entry_out* feo,
                                          struct fuse_entry_bpf_out* febo) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);
    if (IsHiddenLookupTarget(uid, parent, error_in, name)) {
        RuntimeState::ScheduleHiddenEntryInvalidation();
        if (ReplyErrorBridge::Reply(req, ENOENT, "pf_lookup_postfilter").has_value()) {
            return;
        }
        ArmHiddenErrorRemap(req, ENOENT, "pf_lookup_postfilter");
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, uint32_t, const char*,
                                        struct fuse_entry_out*, struct fuse_entry_bpf_out*)>(gOriginalPfLookupPostfilter);
    if (fn) {
        gInPfLookupPostfilter = true;
        fn(req, parent, error_in, name, feo, febo);
        gInPfLookupPostfilter = false;
    }
}

extern "C" void WrappedPfAccess(fuse_req_t req, uint64_t ino, int mask) {
    RuntimeState::RememberFuseSession(req);
    ScopedUid scopedUid(RuntimeState::ReqUid(req));
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, int)>(gOriginalPfAccess);
    if (fn) fn(req, ino, mask);
}

extern "C" void WrappedPfOpen(fuse_req_t req, uint64_t ino, fuse_file_info* fi) {
    RecordMonitorEventIno(req, "OPEN", ino);
    RuntimeState::RememberFuseSession(req);
    uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);

    // 在FUSE层拦截写标志位，通过修改 open flags 让底层文件系统以只读打开，支持fd透传
    if (fi != nullptr) {
        if (auto path = LookupTrackedPathForInode(ino)) {
            if (HiddenPathPolicy::IsReadOnly(uid, *path)) {
                int mode = fi->flags & O_ACCMODE;
                if (mode == O_WRONLY || mode == O_RDWR || (fi->flags & (O_CREAT | O_TRUNC | O_APPEND))) {
                    DebugLogPrint(4, "read-only policy applied for pf_open path=%s uid=%u", path->c_str(), uid);
                    // 移除写入相关的 flag，强制修改为 O_RDONLY
                    fi->flags = (fi->flags & ~O_ACCMODE) | O_RDONLY;
                    fi->flags &= ~(O_CREAT | O_TRUNC | O_APPEND);
                }
            }
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, fuse_file_info*)>(gOriginalPfOpen);
    if (fn) fn(req, ino, fi);
}

extern "C" void WrappedPfOpendir(fuse_req_t req, uint64_t ino, void* fi) {
    RuntimeState::RememberFuseSession(req);
    ScopedUid scopedUid(RuntimeState::ReqUid(req));
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, void*)>(gOriginalPfOpendir);
    if (fn) fn(req, ino, fi);
}

extern "C" void WrappedPfMkdir(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode) {
    RecordMonitorEvent(req, "CREATE", parent, name);
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);
    
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_mkdir", kind, EACCES, ENOENT)) return;

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block mkdir path=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_mkdir").has_value()) return;
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t)>(gOriginalPfMkdir);
    if (fn) fn(req, parent, name, mode);
}

extern "C" void WrappedPfMknod(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode, uint64_t rdev) {
    RecordMonitorEvent(req, "CREATE", parent, name);
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);

    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_mknod", kind, EPERM, ENOENT)) return;

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block mknod path=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_mknod").has_value()) return;
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t, uint64_t)>(gOriginalPfMknod);
    if (fn) fn(req, parent, name, mode, rdev);
}

extern "C" void WrappedPfUnlink(fuse_req_t req, uint64_t parent, const char* name) {
    RecordMonitorEvent(req, "DELETE", parent, name);
    RuntimeState::RememberFuseSession(req);
    uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);

    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_unlink", kind, ENOENT, ENOENT)) return;

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block unlink path=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_unlink").has_value()) return;
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*)>(gOriginalPfUnlink);
    if (fn) fn(req, parent, name);
}

extern "C" void WrappedPfRmdir(fuse_req_t req, uint64_t parent, const char* name) {
    RecordMonitorEvent(req, "DELETE", parent, name);
    RuntimeState::RememberFuseSession(req);
    uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);

    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_rmdir", kind, ENOENT, ENOENT)) return;

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block rmdir path=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_rmdir").has_value()) return;
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*)>(gOriginalPfRmdir);
    if (fn) fn(req, parent, name);
}

extern "C" void WrappedPfRename(fuse_req_t req, uint64_t parent, const char* name, uint64_t new_parent, const char* new_name, uint32_t flags) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);
    const HiddenNamedTargetKind srcKind = ClassifyHiddenNamedTarget(uid, parent, name);
    const HiddenNamedTargetKind dstKind = ClassifyHiddenNamedTarget(uid, new_parent, new_name);
    if (srcKind != HiddenNamedTargetKind::None || dstKind != HiddenNamedTargetKind::None) {
        RuntimeState::ScheduleHiddenEntryInvalidation();
        if (ReplyErrorBridge::Reply(req, ENOENT, "pf_rename").has_value()) return;
        ArmHiddenErrorRemap(req, ENOENT, "pf_rename");
    }

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block rename src=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_rename").has_value()) return;
        }
    }
    if (auto newParentPath = LookupTrackedPathForInode(new_parent)) {
        std::string newChildPath = HiddenPathPolicy::JoinPathComponent(*newParentPath, new_name ? new_name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, newChildPath)) {
            DebugLogPrint(4, "read-only block rename dst=%s", newChildPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_rename").has_value()) return;
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint64_t, const char*, uint32_t)>(gOriginalPfRename);
    if (fn) fn(req, parent, name, new_parent, new_name, flags);
}

extern "C" void WrappedPfCreate(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode, fuse_file_info* fi) {
    RecordMonitorEvent(req, "CREATE", parent, name);
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_create", kind, EPERM, ENOENT)) return;

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block create path=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_create").has_value()) return;
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t, fuse_file_info*)>(gOriginalPfCreate);
    if (fn) fn(req, parent, name, mode, fi);
}

extern "C" void WrappedPfReaddir(fuse_req_t req, uint64_t ino, size_t size, off_t off, void* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*)>(gOriginalPfReaddir);
    if (fn == nullptr) return;
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts[req->unique] = PendingReaddirContext{uid, ino, {}};
    }
    gInPfReaddir = true;
    gPfReaddirUid = uid;
    gPfReaddirIno = ino;
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    fn(req, ino, size, off, fi);
    gCurrentReaddirReqUnique = 0;
    gPfReaddirIno = 0;
    gPfReaddirUid = 0;
    gInPfReaddir = false;
}

extern "C" void WrappedDoReaddirCommon(fuse_req_t req, uint64_t ino, size_t size, off_t off, void* fi, bool plus) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*, bool)>(gOriginalDoReaddirCommon);
    if (fn == nullptr) return;
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts[req->unique] = PendingReaddirContext{uid, ino, {}};
    }
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    fn(req, ino, size, off, fi, plus);
    gCurrentReaddirReqUnique = 0;
}

extern "C" void WrappedPfReaddirplus(fuse_req_t req, uint64_t ino, size_t size, off_t off, void* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*)>(gOriginalPfReaddirplus);
    if (fn == nullptr) return;
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts[req->unique] = PendingReaddirContext{uid, ino, {}};
    }
    gInPfReaddirplus = true;
    gPfReaddirUid = uid;
    gPfReaddirIno = ino;
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    fn(req, ino, size, off, fi);
    gCurrentReaddirReqUnique = 0;
    gPfReaddirIno = 0;
    gPfReaddirUid = 0;
    gInPfReaddirplus = false;
}

extern "C" int WrappedNotifyInvalEntry(void* se, uint64_t parent, const char* name, size_t namelen) {
    auto fn = reinterpret_cast<int (*)(void*, uint64_t, const char*, size_t)>(gOriginalNotifyInvalEntry);
    int ret = fn ? fn(se, parent, name, namelen) : -1;
    return ret;
}

extern "C" int WrappedNotifyInvalInode(void* se, uint64_t ino, off_t off, off_t len) {
    auto fn = reinterpret_cast<int (*)(void*, uint64_t, off_t, off_t)>(gOriginalNotifyInvalInode);
    int ret = fn ? fn(se, ino, off, len) : -1;
    return ret;
}

extern "C" int WrappedReplyEntry(fuse_req_t req, const struct fuse_entry_param* e) {
    auto fn = reinterpret_cast<int (*)(fuse_req_t, const struct fuse_entry_param*)>(gOriginalReplyEntry);
    const bool hiddenLookupForUid = HiddenPathPolicy::IsTestHiddenUid(RuntimeState::ReqUid(req)) &&
                                    (gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup);
    if (hiddenLookupForUid) {
        if (gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup) {
            ArmHiddenCreateLeakRemap(req, "fuse_reply_entry");
        }
        if (gTrackHiddenSubtreeLookup) {
            if (const auto parentPath = LookupTrackedPathForInode(gCurrentLookupParentInode); parentPath.has_value()) {
                RememberTrackedPathForInode(gCurrentLookupParentInode, *parentPath);
                RememberRecentHiddenParentPath(RuntimeState::ReqUid(req), *parentPath);
                RuntimeState::ScheduleHiddenInodeInvalidation(gCurrentLookupParentInode);
            }
        }
        if (auto ret = ReplyErrorBridge::Reply(req, ENOENT, "fuse_reply_entry"); ret.has_value()) {
            RuntimeState::ScheduleHiddenEntryInvalidation();
            if (gCurrentLookupParentInode != 0 && !gCurrentLookupName.empty()) {
                RuntimeState::ScheduleSpecificEntryInvalidation(gCurrentLookupParentInode, gCurrentLookupName);
            }
            if (e != nullptr && e->ino != 0) {
                RuntimeState::ScheduleHiddenInodeInvalidation(e->ino);
            }
            return *ret;
        }
    }
    fuse_entry_param patchedEntry = {};
    const struct fuse_entry_param* replyEntry = e;
    bool forceUncachedReplyEntry = gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup;
    bool exactHiddenTargetReplyEntry = false;
    if (e != nullptr && (gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup)) {
        patchedEntry = *e;
        patchedEntry.entry_timeout = 0.0;
        patchedEntry.attr_timeout = 0.0;
        replyEntry = &patchedEntry;
        RuntimeState::ScheduleHiddenEntryInvalidation();
        if (TrackHiddenSubtreeInode(e->ino)) {
            RuntimeState::ScheduleHiddenInodeInvalidation(e->ino);
        }
    }
    if (e != nullptr && gCurrentLookupParentInode != 0 && !gCurrentLookupName.empty()) {
        std::optional<std::string> childPath;
        if (const auto parentPath = LookupTrackedPathForInode(gCurrentLookupParentInode); parentPath.has_value()) {
            childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, gCurrentLookupName);
        } else if (IsFirstComponentOfHiddenRelativePath(gCurrentLookupName)) {
            childPath = HiddenPathPolicy::JoinPathComponent(kVisibleStorageRoots[0], gCurrentLookupName);
        }
        if (childPath.has_value()) {
            RememberTrackedPathForInode(e->ino, *childPath);
            const bool hiddenSubtreePath = HiddenPathPolicy::IsAnyHiddenSubtreePath(*childPath);
            exactHiddenTargetReplyEntry = HiddenPathPolicy::IsExactHiddenTargetPath(*childPath);
            if (hiddenSubtreePath) {
                TrackHiddenSubtreeInode(e->ino);
                forceUncachedReplyEntry = true;
            }
            if (exactHiddenTargetReplyEntry) {
                forceUncachedReplyEntry = true;
                RuntimeState::ScheduleSpecificEntryInvalidation(gCurrentLookupParentInode, gCurrentLookupName);
                RuntimeState::ScheduleHiddenInodeInvalidation(e->ino);
            }
            if (IsParentOfExactHiddenTargetPath(*childPath)) {
                RememberRecentHiddenParentPath(RuntimeState::ReqUid(req), *childPath);
            }
        }
    }
    if (e != nullptr && forceUncachedReplyEntry && replyEntry == e) {
        patchedEntry = *e;
        patchedEntry.entry_timeout = 0.0;
        patchedEntry.attr_timeout = 0.0;
        replyEntry = &patchedEntry;
    }
    int ret = fn ? fn(req, replyEntry) : -1;
    return ret;
}

extern "C" int WrappedReplyAttr(fuse_req_t req, const struct stat* attr, double timeout) {
    auto fn = reinterpret_cast<int (*)(fuse_req_t, const struct stat*, double)>(gOriginalReplyAttr);
    const double replyTimeout = gZeroAttrCacheForCurrentGetattr ? 0.0 : timeout;
    return fn ? fn(req, attr, replyTimeout) : -1;
}

extern "C" int WrappedReplyBuf(fuse_req_t req, const char* buf, size_t size) {
    auto fn = reinterpret_cast<int (*)(fuse_req_t, const char*, size_t)>(gOriginalReplyBuf);
    const char* replyBuf = buf;
    size_t replySize = size;
    std::vector<char> filteredStorage;
    size_t removedCount = 0;
    std::vector<FilteredDirentMatch> removedEntries;
    PendingReaddirContext pendingContext{};
    bool hasPendingContext = false;
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        const auto it = gPendingReaddirContexts.find(req->unique);
        if (it != gPendingReaddirContexts.end()) {
            pendingContext = it->second;
            hasPendingContext = true;
        }
    }
    const uint32_t reqUid = RuntimeState::ReqUid(req);
    const uint32_t requestFilterUid = gPfReaddirUid != 0 ? gPfReaddirUid : (hasPendingContext && pendingContext.uid != 0 ? pendingContext.uid : reqUid);
    const uint64_t filterIno = gPfReaddirIno != 0 ? gPfReaddirIno : (hasPendingContext ? pendingContext.ino : 0);
    const bool filterPlainReaddir = gInPfReaddir;
    const bool filterPostfilterReaddir = gInPfReaddirPostfilter;
    const bool filterReaddirplus = gInPfReaddirplus;
    const bool requireParentMatch = filterIno != 0;
    uint32_t fallbackHiddenUid = 0;
    const std::optional<std::string> fallbackParentPath = filterIno == 0 ? LookupRecentHiddenParentPath(requestFilterUid, &fallbackHiddenUid) : std::nullopt;
    const bool canBorrowFallbackUid = requestFilterUid == 0 && HiddenPathPolicy::IsTestHiddenUid(fallbackHiddenUid);
    const uint32_t filterUid = HiddenPathPolicy::IsTestHiddenUid(requestFilterUid) ? requestFilterUid : (canBorrowFallbackUid ? fallbackHiddenUid : 0);

    if (filterIno != 0 && !pendingContext.path.empty()) {
        RememberTrackedPathForInode(filterIno, pendingContext.path);
    }

    if (HiddenPathPolicy::IsTestHiddenUid(filterUid)) {
        if (filterPlainReaddir) {
            if (DirentFilter::BuildFilteredDirentPayload(buf, size, filterUid, filterIno, &filteredStorage, &removedCount, requireParentMatch)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
            }
        } else if (filterReaddirplus) {
            if (DirentFilter::BuildFilteredDirentplusPayload(buf, size, filterUid, filterIno, &filteredStorage, &removedCount, requireParentMatch)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
            }
        } else if (filterPostfilterReaddir && size >= sizeof(fuse_read_out)) {
            const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
            const size_t payloadSize = std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
            std::vector<char> filteredPayload;
            if (DirentFilter::BuildFilteredDirentPayload(buf + sizeof(fuse_read_out), payloadSize, filterUid, filterIno, &filteredPayload, &removedCount, requireParentMatch)) {
                fuse_read_out patched = *readOut;
                patched.size = static_cast<uint32_t>(filteredPayload.size());
                filteredStorage.resize(sizeof(patched) + filteredPayload.size());
                std::memcpy(filteredStorage.data(), &patched, sizeof(patched));
                std::memcpy(filteredStorage.data() + sizeof(patched), filteredPayload.data(), filteredPayload.size());
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
            }
        }

        if (replyBuf == buf) {
            if (fallbackParentPath.has_value() && BuildFilteredDirentplusPayloadForParentPath(buf, size, filterUid, *fallbackParentPath, &filteredStorage, &removedCount, &removedEntries)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                InvalidateFilteredParentChildren(*fallbackParentPath, removedEntries);
                ClearRecentHiddenParentPath(filterUid);
            } else if (fallbackParentPath.has_value() && BuildFilteredDirentPayloadForParentPath(buf, size, filterUid, *fallbackParentPath, &filteredStorage, &removedCount, &removedEntries)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                InvalidateFilteredParentChildren(*fallbackParentPath, removedEntries);
                ClearRecentHiddenParentPath(filterUid);
            } else if (size >= sizeof(fuse_read_out) && fallbackParentPath.has_value()) {
                const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
                const size_t payloadSize = std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
                std::vector<char> filteredPayload;
                if (BuildFilteredDirentPayloadForParentPath(buf + sizeof(fuse_read_out), payloadSize, filterUid, *fallbackParentPath, &filteredPayload, &removedCount, &removedEntries)) {
                    fuse_read_out patched = *readOut;
                    patched.size = static_cast<uint32_t>(filteredPayload.size());
                    filteredStorage.resize(sizeof(patched) + filteredPayload.size());
                    std::memcpy(filteredStorage.data(), &patched, sizeof(patched));
                    std::memcpy(filteredStorage.data() + sizeof(patched), filteredPayload.data(), filteredPayload.size());
                    replyBuf = filteredStorage.data();
                    replySize = filteredStorage.size();
                    InvalidateFilteredParentChildren(*fallbackParentPath, removedEntries);
                    ClearRecentHiddenParentPath(filterUid);
                }
            }
        }

        if (replyBuf == buf) {
            if (DirentFilter::BuildFilteredDirentplusPayload(buf, size, filterUid, 0, &filteredStorage, &removedCount, false)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
            } else if (DirentFilter::BuildFilteredDirentPayload(buf, size, filterUid, 0, &filteredStorage, &removedCount, false)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
            } else if (size >= sizeof(fuse_read_out)) {
                const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
                const size_t payloadSize = std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
                std::vector<char> filteredPayload;
                if (DirentFilter::BuildFilteredDirentPayload(buf + sizeof(fuse_read_out), payloadSize, filterUid, 0, &filteredPayload, &removedCount, false)) {
                    fuse_read_out patched = *readOut;
                    patched.size = static_cast<uint32_t>(filteredPayload.size());
                    filteredStorage.resize(sizeof(patched) + filteredPayload.size());
                    std::memcpy(filteredStorage.data(), &patched, sizeof(patched));
                    std::memcpy(filteredStorage.data() + sizeof(patched), filteredPayload.data(), filteredPayload.size());
                    replyBuf = filteredStorage.data();
                    replySize = filteredStorage.size();
                }
            }
        }
    }

    int ret = fn ? fn(req, replyBuf, replySize) : -1;
    if (hasPendingContext && req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts.erase(req->unique);
    }
    return ret;
}

extern "C" int WrappedReplyErr(fuse_req_t req, int err) {
    auto fn = ReplyErrorBridge::Original();
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts.erase(req->unique);
    }
    err = MaybeRewriteHiddenLeakErrno(req, err, "fuse_reply_err");
    int ret = fn ? fn(req, err) : -1;
    return ret;
}

extern "C" void WrappedPfGetattr(fuse_req_t req, uint64_t ino, void* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    ScopedUid scopedUid(uid);
    gZeroAttrCacheForCurrentGetattr = IsTrackedHiddenSubtreeInode(ino);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, void*)>(gOriginalPfGetattr);
    if (fn) {
        gInPfGetattr = true;
        gPfGetattrUid = uid;
        gPfGetattrIno = ino;
        fn(req, ino, fi);
        gPfGetattrIno = 0;
        gPfGetattrUid = 0;
        gInPfGetattr = false;
        gZeroAttrCacheForCurrentGetattr = false;
    }
}

extern "C" int WrappedLstat(const char* path, struct stat* st) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (gInPfGetattr && gPfGetattrIno != 0 && HiddenPathPolicy::IsHiddenRootDirectoryPath(pathView)) {
        uint64_t expected = 0;
        const bool recorded = gHiddenRootParentInode.compare_exchange_strong(expected, gPfGetattrIno, std::memory_order_relaxed);
        RemoveTrackedHiddenSubtreeInode(gPfGetattrIno);
        if (recorded && CurrentHideConfig()->enableHideAllRootEntries) {
            RuntimeState::ScheduleHiddenEntryInvalidation();
        }
    }
    NoteHiddenSubtreePathForCache(pathView);
    if (gInPfGetattr && HiddenPathPolicy::IsTestHiddenUid(gPfGetattrUid)) {
        if (HiddenPathPolicy::ShouldHideTestPath(gPfGetattrUid, pathView)) {
            errno = ENOENT;
            return -1;
        }
    }
    auto fn = reinterpret_cast<int (*)(const char*, struct stat*)>(gOriginalLstat);
    if (fn) {
        const int ret = fn(path, st);
        if (ret == 0 && gInPfGetattr && gPfGetattrIno != 0) {
            RememberTrackedPathForInode(gPfGetattrIno, pathView);
            if (HiddenPathPolicy::IsTestHiddenUid(gPfGetattrUid) && IsParentOfExactHiddenTargetPath(pathView)) {
                RememberRecentHiddenParentPath(gPfGetattrUid, pathView);
            }
            if (HiddenPathPolicy::IsAnyHiddenSubtreePath(pathView)) {
                TrackHiddenSubtreeInode(gPfGetattrIno);
            }
        }
        return ret;
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedStat(const char* path, struct stat* st) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (gInPfReaddirPostfilter && HiddenPathPolicy::IsTestHiddenUid(gPfReaddirUid) && HiddenPathPolicy::IsAnyHiddenSubtreePath(pathView)) {
        errno = ENOENT;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*, struct stat*)>(gOriginalStat);
    if (fn) {
        return fn(path, st);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" ssize_t WrappedGetxattr(const char* path, const char* name, void* value, size_t size) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (ShouldHideLowerFsPath(pathView)) {
        errno = ENOENT;
        return -1;
    }
    auto fn = reinterpret_cast<ssize_t (*)(const char*, const char*, void*, size_t)>(gOriginalGetxattr);
    if (fn) {
        return fn(path, name, value, size);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" ssize_t WrappedLgetxattr(const char* path, const char* name, void* value, size_t size) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (ShouldHideLowerFsPath(pathView)) {
        errno = ENOENT;
        return -1;
    }
    auto fn = reinterpret_cast<ssize_t (*)(const char*, const char*, void*, size_t)>(gOriginalLgetxattr);
    if (fn) {
        return fn(path, name, value, size);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedMkdirLibc(const char* path, mode_t mode) {
    RecordMonitorEventPath(gActiveUid, "CREATE", path);
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (ShouldHideLowerFsCreatePath(pathView)) {
        errno = EACCES;
        return -1;
    }
    if (HiddenPathPolicy::IsReadOnly(gActiveUid, std::string(pathView))) {
        errno = EROFS;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*, mode_t)>(gOriginalMkdir);
    if (fn) {
        return fn(path, mode);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedMknod(const char* path, mode_t mode, dev_t dev) {
    RecordMonitorEventPath(gActiveUid, "CREATE", path);
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (ShouldHideLowerFsCreatePath(pathView)) {
        errno = EPERM;
        return -1;
    }
    if (HiddenPathPolicy::IsReadOnly(gActiveUid, std::string(pathView))) {
        errno = EROFS;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*, mode_t, dev_t)>(gOriginalMknod);
    if (fn) {
        return fn(path, mode, dev);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedOpen(const char* path, int flags, ...) {
    if ((flags & O_CREAT) == 0) {
        RecordMonitorEventPath(gActiveUid, "OPEN", path);
    } else {
        RecordMonitorEventPath(gActiveUid, "CREATE", path);
    }
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list args;
        va_start(args, flags);
        mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
    }
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if ((flags & O_CREAT) != 0 && ShouldHideLowerFsCreatePath(pathView)) {
        errno = EPERM;
        return -1;
    }
    if (HiddenPathPolicy::IsReadOnly(gActiveUid, std::string(pathView))) {
        int accmode = flags & O_ACCMODE;
        if (accmode == O_WRONLY || accmode == O_RDWR || (flags & (O_CREAT | O_TRUNC | O_APPEND))) {
            errno = EROFS;
            return -1;
        }
    }
    auto fn = reinterpret_cast<int (*)(const char*, int, ...)>(gOriginalOpen);
    if (fn) {
        if ((flags & O_CREAT) != 0) {
            return fn(path, flags, mode);
        }
        return fn(path, flags);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedOpen2(const char* path, int flags) {
    if ((flags & O_CREAT) == 0) {
        RecordMonitorEventPath(gActiveUid, "OPEN", path);
    } else {
        RecordMonitorEventPath(gActiveUid, "CREATE", path);
    }
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if ((flags & O_CREAT) != 0 && ShouldHideLowerFsCreatePath(pathView)) {
        errno = EPERM;
        return -1;
    }
    if (HiddenPathPolicy::IsReadOnly(gActiveUid, std::string(pathView))) {
        int accmode = flags & O_ACCMODE;
        if (accmode == O_WRONLY || accmode == O_RDWR || (flags & (O_CREAT | O_TRUNC | O_APPEND))) {
            errno = EROFS;
            return -1;
        }
    }
    auto fn = reinterpret_cast<int (*)(const char*, int)>(gOriginalOpen2);
    if (fn) {
        return fn(path, flags);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedUnlinkLibc(const char* path) {
    RecordMonitorEventPath(gActiveUid, "DELETE", path);
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (HiddenPathPolicy::IsReadOnly(gActiveUid, std::string(pathView))) {
        errno = EROFS;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*)>(gOriginalUnlinkLibc);
    if (fn) return fn(path);
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedRmdirLibc(const char* path) {
    RecordMonitorEventPath(gActiveUid, "DELETE", path);
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (HiddenPathPolicy::IsReadOnly(gActiveUid, std::string(pathView))) {
        errno = EROFS;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*)>(gOriginalRmdirLibc);
    if (fn) return fn(path);
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedRenameLibc(const char* oldpath, const char* newpath) {
    RecordMonitorEventPath(gActiveUid, "RENAME", oldpath);
    const std::string_view oldView = oldpath != nullptr ? std::string_view(oldpath) : std::string_view();
    const std::string_view newView = newpath != nullptr ? std::string_view(newpath) : std::string_view();
    if (HiddenPathPolicy::IsReadOnly(gActiveUid, std::string(oldView)) || HiddenPathPolicy::IsReadOnly(gActiveUid, std::string(newView))) {
        errno = EROFS;
        return -1;
    }
    auto fn = reinterpret_cast<int (*)(const char*, const char*)>(gOriginalRenameLibc);
    if (fn) return fn(oldpath, newpath);
    errno = ENOSYS;
    return -1;
}

bool WrappedIsAppAccessiblePath(void* fuse, const std::string& path, uint32_t uid) {
    if (gOriginalIsAppAccessiblePath == nullptr) {
        return false;
    }
    gLastPathPolicyUid = uid;
    gLastPathPolicyPath = path;
    if (!UnicodePolicy::NeedsSanitization(path)) {
        UnicodePolicy::LogSuspiciousDirectPath("app_accessible", path);
        NoteHiddenSubtreePathForCache(path);
        if (HiddenPathPolicy::ShouldHideTestPath(uid, path)) {
            return false;
        }
        return gOriginalIsAppAccessiblePath(fuse, path, uid);
    }
    std::string sanitized(path);
    UnicodePolicy::RewriteString(sanitized);
    gLastPathPolicyPath = sanitized;
    NoteHiddenSubtreePathForCache(sanitized);
    if (HiddenPathPolicy::ShouldHideTestPath(uid, sanitized)) {
        return false;
    }
    return gOriginalIsAppAccessiblePath(fuse, sanitized, uid);
}

bool WrappedIsPackageOwnedPath(const std::string& lhs, const std::string& rhs) {
    if (gOriginalIsPackageOwnedPath == nullptr) {
        return false;
    }
    if (!UnicodePolicy::NeedsSanitization(lhs)) {
        UnicodePolicy::LogSuspiciousDirectPath("package_owned", lhs);
        return gOriginalIsPackageOwnedPath(lhs, rhs);
    }
    std::string sanitizedLhs(lhs);
    UnicodePolicy::RewriteString(sanitizedLhs);
    return gOriginalIsPackageOwnedPath(sanitizedLhs, rhs);
}

bool WrappedIsBpfBackingPath(const std::string& path) {
    if (gOriginalIsBpfBackingPath == nullptr) {
        return false;
    }
    if (!UnicodePolicy::NeedsSanitization(path)) {
        UnicodePolicy::LogSuspiciousDirectPath("bpf_backing", path);
        return gOriginalIsBpfBackingPath(path);
    }
    std::string sanitized(path);
    UnicodePolicy::RewriteString(sanitized);
    return gOriginalIsBpfBackingPath(sanitized);
}

extern "C" int WrappedStrcasecmp(const char* lhs, const char* rhs) {
    const size_t lhsLen = (lhs != nullptr) ? std::strlen(lhs) : 0;
    const size_t rhsLen = (rhs != nullptr) ? std::strlen(rhs) : 0;
    const int result = UnicodePolicy::CompareCaseFoldIgnoringDefaultIgnorables(
        reinterpret_cast<const uint8_t*>(lhs ? lhs : ""), lhsLen,
        reinterpret_cast<const uint8_t*>(rhs ? rhs : ""), rhsLen);
    return result;
}

extern "C" bool WrappedEqualsIgnoreCaseAbi(const char* lhsData, size_t lhsSize, const char* rhsData,
                                           size_t rhsSize) {
    const int result = UnicodePolicy::CompareCaseFoldIgnoringDefaultIgnorables(
        reinterpret_cast<const uint8_t*>(lhsData ? lhsData : ""), lhsSize,
        reinterpret_cast<const uint8_t*>(rhsData ? rhsData : ""), rhsSize);
    return result == 0;
}

}  // namespace fusehide
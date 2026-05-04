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

    const size_t before = entries.size();
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

    if (fi != nullptr) {
        if (auto path = LookupTrackedPathForInode(ino)) {
            if (HiddenPathPolicy::IsReadOnly(uid, *path)) {
                if ((fi->flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) != 0) {
                    DebugLogPrint(4, "read-only policy applied for pf_open path=%s uid=%u", path->c_str(), uid);
                    fi->flags &= ~(O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND);
                    fi->flags |= O_RDONLY;
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
            if (ReplyErrorBridge::Reply(req, EACCES, "pf_mkdir").has_value()) return;
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
            if (ReplyErrorBridge::Reply(req, EACCES, "pf_mknod").has_value()) return;
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
            if (ReplyErrorBridge::Reply(req, EACCES, "pf_unlink").has_value()) return;
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
            if (ReplyErrorBridge::Reply(req, EACCES, "pf_rmdir").has_value()) return;
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
            if (ReplyErrorBridge::Reply(req, EACCES, "pf_rename").has_value()) return;
        }
    }
    if (auto newParentPath = LookupTrackedPathForInode(new_parent)) {
        std::string newChildPath = HiddenPathPolicy::JoinPathComponent(*newParentPath, new_name ? new_name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, newChildPath)) {
            if (ReplyErrorBridge::Reply(req, EACCES, "pf_rename").has_value()) return;
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
            if (ReplyErrorBridge::Reply(req, EACCES, "pf_create").has_value()) return;
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

std::string NormalizeLowerPathToFuse(const std::string& path) {
    if (path.starts_with("/data/media/0")) return "/storage/emulated/0" + path.substr(13);
    if (path.starts_with("/mnt/pass_through/0/emulated/0")) return "/storage/emulated/0" + path.substr(30);
    return path;
}

std::string NormalizeFuseToLowerPath(const std::string& path, const std::string& originalLower) {
    if (path.starts_with("/storage/emulated/0")) {
        if (originalLower.starts_with("/data/media/0")) return "/data/media/0" + path.substr(19);
        if (originalLower.starts_with("/mnt/pass_through/0/emulated/0")) return "/mnt/pass_through/0/emulated/0" + path.substr(19);
    }
    return path;
}

std::string ProcessRedirectPath(const char* path, uint32_t uid) {
    if (!path || uid == 0) return path ? path : "";
    std::string lowerPath = path;
    std::string fusePath = NormalizeLowerPathToFuse(lowerPath);
    std::string targetFuse = HiddenPathPolicy::GetRedirectTarget(uid, fusePath);
    if (!targetFuse.empty() && targetFuse != fusePath) {
        std::string res = NormalizeFuseToLowerPath(targetFuse, lowerPath);
        DebugLogPrint(4, "redirect applied: uid=%u %s -> %s", uid, path, res.c_str());
        return res;
    }
    return lowerPath;
}

extern "C" int WrappedMkdirLibc(const char* path, mode_t mode) {
    RecordMonitorEventPath(gActiveUid, "CREATE", path);
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (ShouldHideLowerFsCreatePath(pathView)) {
        errno = EACCES;
        return -1;
    }
    std::string actualPath = ProcessRedirectPath(path, gActiveUid);
    auto fn = reinterpret_cast<int (*)(const char*, mode_t)>(gOriginalMkdir);
    if (fn) {
        return fn(actualPath.c_str(), mode);
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
    std::string actualPath = ProcessRedirectPath(path, gActiveUid);
    auto fn = reinterpret_cast<int (*)(const char*, mode_t, dev_t)>(gOriginalMknod);
    if (fn) {
        return fn(actualPath.c_str(), mode, dev);
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
    std::string actualPath = ProcessRedirectPath(path, gActiveUid);
    auto fn = reinterpret_cast<int (*)(const char*, int, ...)>(gOriginalOpen);
    if (fn) {
        if ((flags & O_CREAT) != 0) {
            return fn(actualPath.c_str(), flags, mode);
        }
        return fn(actualPath.c_str(), flags);
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
    std::string actualPath = ProcessRedirectPath(path, gActiveUid);
    auto fn = reinterpret_cast<int (*)(const char*, int)>(gOriginalOpen2);
    if (fn) {
        return fn(actualPath.c_str(), flags);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedUnlinkLibc(const char* path) {
    RecordMonitorEventPath(gActiveUid, "DELETE", path);
    std::string actualPath = ProcessRedirectPath(path, gActiveUid);
    auto fn = reinterpret_cast<int (*)(const char*)>(gOriginalUnlinkLibc);
    if (fn) return fn(actualPath.c_str());
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedRmdirLibc(const char* path) {
    RecordMonitorEventPath(gActiveUid, "DELETE", path);
    std::string actualPath = ProcessRedirectPath(path, gActiveUid);
    auto fn = reinterpret_cast<int (*)(const char*)>(gOriginalRmdirLibc);
    if (fn) return fn(actualPath.c_str());
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedRenameLibc(const char* oldpath, const char* newpath) {
    RecordMonitorEventPath(gActiveUid, "RENAME", oldpath);
    std::string sOld = ProcessRedirectPath(oldpath, gActiveUid);
    std::string sNew = ProcessRedirectPath(newpath, gActiveUid);
    auto fn = reinterpret_cast<int (*)(const char*, const char*)>(gOriginalRenameLibc);
    if (fn) return fn(sOld.c_str(), sNew.c_str());
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


===== File: cpp/fusehide/runtime_state.cpp =====
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

#include "state.hpp"
#include <fnmatch.h>

namespace fusehide {

void* gOriginalPfLookup = nullptr;
void* gOriginalPfLookupPostfilter = nullptr;
void* gOriginalPfAccess = nullptr;
void* gOriginalPfOpen = nullptr;
void* gOriginalPfOpendir = nullptr;
void* gOriginalPfMknod = nullptr;
void* gOriginalPfMkdir = nullptr;
void* gOriginalPfUnlink = nullptr;
void* gOriginalPfRmdir = nullptr;
void* gOriginalPfRename = nullptr;
void* gOriginalPfCreate = nullptr;
void* gOriginalPfReaddir = nullptr;
void* gOriginalPfReaddirPostfilter = nullptr;
void* gOriginalPfReaddirplus = nullptr;
void* gOriginalDoReaddirCommon = nullptr;
void* gOriginalPfGetattr = nullptr;
void* gOriginalOpen = nullptr;
void* gOriginalOpen2 = nullptr;
void* gOriginalMkdir = nullptr;
void* gOriginalMknod = nullptr;
void* gOriginalLstat = nullptr;
void* gOriginalStat = nullptr;
void* gOriginalGetxattr = nullptr;
void* gOriginalLgetxattr = nullptr;
void* gOriginalShouldNotCache = nullptr;
void* gOriginalNotifyInvalEntry = nullptr;
void* gOriginalNotifyInvalInode = nullptr;
void* gOriginalReplyAttr = nullptr;
void* gOriginalReplyEntry = nullptr;
void* gOriginalReplyBuf = nullptr;
void* gOriginalReplyErr = nullptr;
void* gOriginalGetDirectoryEntries = nullptr;
void* gOriginalAddDirectoryEntriesFromLowerFs = nullptr;
std::atomic<void*> gLastFuseSession{nullptr};
std::atomic<bool> gHiddenEntryInvalidationPending{false};
std::atomic<uint64_t> gHiddenRootParentInode{0};
thread_local bool gInPfLookup = false;
thread_local bool gInPfLookupPostfilter = false;
thread_local bool gInPfReaddir = false;
thread_local bool gInPfReaddirPostfilter = false;
thread_local bool gInPfReaddirplus = false;
thread_local bool gInPfGetattr = false;
thread_local uint32_t gPfGetattrUid = 0;
thread_local uint32_t gPfReaddirUid = 0;
thread_local uint64_t gPfGetattrIno = 0;
thread_local uint64_t gPfReaddirIno = 0;
thread_local uint64_t gCurrentLookupParentInode = 0;
thread_local std::string gCurrentLookupName;
thread_local bool gTrackRootHiddenLookup = false;
thread_local bool gTrackHiddenSubtreeLookup = false;
thread_local bool gZeroAttrCacheForCurrentGetattr = false;
thread_local fuse_req_t gPendingHiddenErrReq = nullptr;
thread_local uint64_t gPendingHiddenErrReqUnique = 0;
thread_local int gPendingHiddenErrno = 0;
thread_local uint64_t gCurrentReaddirReqUnique = 0;

std::mutex gMonitorMutex;
std::vector<std::string> gMonitorQueue;

extern "C" void RecordMonitorEvent(fuse_req_t req, const char* type, uint64_t parentIno, const char* name) {
    if (!gMonitorEnabled.load(std::memory_order_relaxed)) return;
    uint32_t uid = req != nullptr ? RuntimeState::ReqUid(req) : 0;
    std::string path;
    if (auto parentPath = LookupTrackedPathForInode(parentIno)) {
        path = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
    } else {
        path = "ino:" + std::to_string(parentIno) + "/" + (name ? name : "");
    }
    std::lock_guard<std::mutex> lock(gMonitorMutex);
    if (gMonitorQueue.size() < 2000) {
        gMonitorQueue.push_back(std::string(type) + "|" + std::to_string(uid) + "|" + path);
    }
}

extern "C" void RecordMonitorEventIno(fuse_req_t req, const char* type, uint64_t ino) {
    if (!gMonitorEnabled.load(std::memory_order_relaxed)) return;
    uint32_t uid = req != nullptr ? RuntimeState::ReqUid(req) : 0;
    std::string path;
    if (auto p = LookupTrackedPathForInode(ino)) {
        path = *p;
    } else {
        path = "ino:" + std::to_string(ino);
    }
    std::lock_guard<std::mutex> lock(gMonitorMutex);
    if (gMonitorQueue.size() < 2000) {
        gMonitorQueue.push_back(std::string(type) + "|" + std::to_string(uid) + "|" + path);
    }
}

extern "C" void RecordMonitorEventPath(uint32_t uid, const char* type, const char* path) {
    if (!gMonitorEnabled.load(std::memory_order_relaxed)) return;
    std::lock_guard<std::mutex> lock(gMonitorMutex);
    if (gMonitorQueue.size() < 2000) {
        gMonitorQueue.push_back(std::string(type) + "|" + std::to_string(uid) + "|" + (path ? path : ""));
    }
}

namespace ReplyErrorBridge {

namespace {

void LogFallbackFailure(const char* caller) {
    if (ShouldLogLimited(gReplyErrFallbackLogCount, 8)) {
        __android_log_print(6, kLogTag,
                            "%s could not resolve fuse_reply_err; delegating to the original path",
                            caller);
    }
}

}  // namespace

FuseReplyErrFn Original() {
    return reinterpret_cast<FuseReplyErrFn>(gOriginalReplyErr);
}

FuseReplyErrFn Resolve() {
    if (auto replyErr = Original(); replyErr != nullptr) {
        return replyErr;
    }

    static std::atomic<void*> sResolvedReplyErr{nullptr};
    void* cached = sResolvedReplyErr.load(std::memory_order_acquire);
    if (cached != nullptr) {
        return reinterpret_cast<FuseReplyErrFn>(cached);
    }

    void* resolved = dlsym(RTLD_DEFAULT, "fuse_reply_err");
    if (resolved == nullptr) {
        return nullptr;
    }

    sResolvedReplyErr.store(resolved, std::memory_order_release);
    return reinterpret_cast<FuseReplyErrFn>(resolved);
}

std::optional<int> Reply(fuse_req_t req, int err, const char* caller) {
    auto replyErr = Resolve();
    if (replyErr == nullptr) {
        LogFallbackFailure(caller);
        return std::nullopt;
    }
    return replyErr(req, err);
}

}  // namespace ReplyErrorBridge

std::mutex gHiddenSubtreeInodesMutex;
std::unordered_set<uint64_t> gHiddenSubtreeInodes;
std::mutex gInodePathCacheMutex;
std::unordered_map<uint64_t, std::string> gInodePathCache;
std::mutex gPendingReaddirContextsMutex;
std::unordered_map<uint64_t, PendingReaddirContext> gPendingReaddirContexts;
std::mutex gRecentHiddenParentPathsMutex;
std::unordered_map<uint32_t, std::string> gRecentHiddenParentPaths;
std::unordered_map<uint32_t, uint32_t> gRecentHiddenParentPathUids;
std::string gRecentHiddenParentPathAnyUid;
uint32_t gRecentHiddenParentPathAnyUidOwner = 0;
std::mutex gUidErrRemapMutex;

struct UidErrRemapState {
    int baselineErr = 0;
    std::chrono::steady_clock::time_point expiresAt{};
    uint32_t pendingCount = 0;
};

std::unordered_map<uint32_t, UidErrRemapState> gUidErrRemapStates;

namespace {

bool HasNonAsciiByte(std::string_view value) {
    for (unsigned char ch : value) {
        if ((ch & 0x80u) != 0) {
            return true;
        }
    }
    return false;
}

std::string NormalizeRelativeHiddenPath(std::string_view path) {
    size_t begin = 0;
    size_t end = path.size();
    while (begin < end && path[begin] == '/') {
        begin++;
    }
    while (end > begin && path[end - 1] == '/') {
        end--;
    }
    std::string normalized;
    normalized.reserve(end - begin);
    bool previousSlash = false;
    for (size_t i = begin; i < end; ++i) {
        const char ch = path[i];
        if (ch == '/') {
            if (previousSlash) {
                continue;
            }
            previousSlash = true;
        } else {
            previousSlash = false;
        }
        normalized.push_back(ch);
    }
    return normalized;
}

std::optional<std::string> RelativePathForVisibleRoot(std::string_view path) {
    for (const auto& root : kVisibleStorageRoots) {
        if (path == root) {
            return std::string();
        }
        if (path.size() > root.size() && path.compare(0, root.size(), root) == 0 &&
            path[root.size()] == '/') {
            return NormalizeRelativeHiddenPath(path.substr(root.size() + 1));
        }
    }
    return std::nullopt;
}

bool MatchesRelativeHiddenPathList(std::string_view relativePath, bool exactOnly) {
    const std::string normalized = NormalizeRelativeHiddenPath(relativePath);
    if (normalized.empty()) {
        return false;
    }
    const auto config = CurrentHideConfig();
    for (const auto& configuredPath : config->hiddenRelativePaths) {
        const std::string candidate = NormalizeRelativeHiddenPath(configuredPath);
        if (candidate.empty()) {
            continue;
        }
        if (normalized == candidate) {
            return true;
        }
        if (!exactOnly && normalized.size() > candidate.size() &&
            normalized.compare(0, candidate.size(), candidate) == 0 &&
            normalized[candidate.size()] == '/') {
            return true;
        }
    }
    return false;
}

bool IsWildcardRootEntryCandidate(std::string_view name) {
    if (name.empty() || name == "." || name == "..") {
        return false;
    }
    if (name.find('/') != std::string_view::npos) {
        return false;
    }
    const auto config = CurrentHideConfig();
    for (const auto& exemptEntry : config->hideAllRootEntriesExemptions) {
        if (name == exemptEntry) {
            return false;
        }
    }
    return true;
}

bool ShouldHideWildcardRootEntryByParent(uint64_t parent, uint64_t rootParent,
                                         std::string_view name) {
    return CurrentHideConfig()->enableHideAllRootEntries && rootParent != 0 &&
           parent == rootParent && IsWildcardRootEntryCandidate(name);
}

}  // namespace

uint32_t RuntimeState::ReqUid(fuse_req_t req) {
    if (req == nullptr) {
        return 0;
    }
    return *reinterpret_cast<const uint32_t*>(reinterpret_cast<const uint8_t*>(req) + 0x3c);
}

void RuntimeState::RememberFuseSession(fuse_req_t req) {
    if (req != nullptr && req->se != nullptr) {
        gLastFuseSession.store(req->se, std::memory_order_relaxed);
    }
}

void RuntimeState::ScheduleHiddenEntryInvalidation() {
    auto notifyEntry =
        reinterpret_cast<int (*)(void*, uint64_t, const char*, size_t)>(gOriginalNotifyInvalEntry);
    void* session = gLastFuseSession.load(std::memory_order_relaxed);
    if (notifyEntry == nullptr || session == nullptr) {
        return;
    }
    if (gHiddenEntryInvalidationPending.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    const uint64_t parent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (parent == 0) {
        gHiddenEntryInvalidationPending.store(false, std::memory_order_release);
        return;
    }
    std::thread([notifyEntry, session]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
        const auto config = CurrentHideConfig();
        std::unordered_set<std::string> namesToInvalidate;
        for (const auto& rootEntryName : config->hiddenRootEntryNames) {
            namesToInvalidate.emplace(rootEntryName);
        }

        if (config->enableHideAllRootEntries) {
            for (const auto& rootPath : kVisibleStorageRoots) {
                DIR* dir = opendir(std::string(rootPath).c_str());
                if (dir == nullptr) {
                    continue;
                }
                while (dirent* entry = readdir(dir)) {
                    const std::string_view name(entry->d_name);
                    if (IsWildcardRootEntryCandidate(name)) {
                        namesToInvalidate.emplace(name);
                    }
                }
                closedir(dir);
            }
        }

        for (const auto& name : namesToInvalidate) {
            const int ret = notifyEntry(session, rootParent, name.c_str(), name.size());
        }
        gHiddenEntryInvalidationPending.store(false, std::memory_order_release);
    }).detach();
}

void RuntimeState::ScheduleSpecificEntryInvalidation(uint64_t parent, std::string_view name) {
    auto notifyEntry =
        reinterpret_cast<int (*)(void*, uint64_t, const char*, size_t)>(gOriginalNotifyInvalEntry);
    void* session = gLastFuseSession.load(std::memory_order_relaxed);
    if (notifyEntry == nullptr || session == nullptr || parent == 0 || name.empty()) {
        return;
    }
    const std::string ownedName(name);
    std::thread([notifyEntry, session, parent, ownedName]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        const int ret = notifyEntry(session, parent, ownedName.c_str(), ownedName.size());
    }).detach();
}

void RuntimeState::ScheduleHiddenInodeInvalidation(uint64_t ino) {
    auto notifyInode =
        reinterpret_cast<int (*)(void*, uint64_t, off_t, off_t)>(gOriginalNotifyInvalInode);
    void* session = gLastFuseSession.load(std::memory_order_relaxed);
    if (notifyInode == nullptr || session == nullptr || ino == 0) {
        return;
    }
    std::thread([notifyInode, session, ino]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        const int ret = notifyInode(session, ino, 0, 0);
    }).detach();
}

std::string InodePath(uint64_t ino) {
    if (ino == 1)
        return "(ROOT)";
    char buf[64];
    std::snprintf(buf, sizeof(buf), "(%p)", (void*)ino);
    return std::string(buf);
}

bool IsHiddenLookupTarget(uint32_t uid, uint64_t parent, uint32_t error_in, const char* name) {
    if (!IsTestHiddenUid(uid) || error_in != 0 || name == nullptr) {
        return false;
    }
    if (IsHiddenLookupCacheTarget(parent, name)) {
        return true;
    }
    const auto kind = ClassifyHiddenNamedTarget(uid, parent, name);
    return kind == HiddenNamedTargetKind::Root || kind == HiddenNamedTargetKind::Descendant;
}

bool IsHiddenLookupCacheTarget(uint64_t parent, const char* name) {
    if (name == nullptr) {
        return false;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (ShouldHideWildcardRootEntryByParent(parent, rootParent, name)) {
        return true;
    }
    return IsConfiguredHiddenRootEntryName(name) && (rootParent == 0 || parent == rootParent);
}

std::optional<HiddenNamedTargetKind> ClassifyHiddenNamedTargetByTrackedPath(uint64_t parent,
                                                                            const char* name) {
    if (name == nullptr) {
        return std::nullopt;
    }
    const auto parentPath = LookupTrackedPathForInode(parent);
    if (!parentPath.has_value()) {
        return std::nullopt;
    }
    const std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name);
    if (HiddenPathPolicy::IsExactHiddenTargetPath(childPath)) {
        return HiddenNamedTargetKind::Root;
    }
    if (HiddenPathPolicy::IsAnyHiddenSubtreePath(childPath)) {
        return HiddenNamedTargetKind::Descendant;
    }
    return std::nullopt;
}

HiddenNamedTargetKind ClassifyHiddenNamedTarget(uint32_t uid, uint64_t parent, const char* name) {
    if (!IsTestHiddenUid(uid) || name == nullptr) {
        return HiddenNamedTargetKind::None;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (parent != 0 && parent != rootParent && IsTrackedHiddenSubtreeInode(parent)) {
        return HiddenNamedTargetKind::Descendant;
    }
    if (ShouldHideWildcardRootEntryByParent(parent, rootParent, name)) {
        return HiddenNamedTargetKind::Root;
    }
    if (IsConfiguredHiddenRootEntryName(name) && (rootParent == 0 || parent == rootParent)) {
        return HiddenNamedTargetKind::Root;
    }
    if (const auto trackedPathKind = ClassifyHiddenNamedTargetByTrackedPath(parent, name);
        trackedPathKind.has_value()) {
        return *trackedPathKind;
    }
    return HiddenNamedTargetKind::None;
}

bool ReplyHiddenNamedTargetError(fuse_req_t req, const char* opName, HiddenNamedTargetKind kind,
                                 int rootErr, int descendantErr) {
    if (kind == HiddenNamedTargetKind::None) {
        return false;
    }
    const int err = kind == HiddenNamedTargetKind::Root ? rootErr : descendantErr;
    if (ReplyErrorBridge::Reply(req, err, opName).has_value()) {
        return true;
    }
    ArmHiddenErrorRemap(req, err, opName);
    return false;
}

namespace {

bool IsExistenceLeakErrno(int err) {
    switch (err) {
        case EEXIST:
        case EISDIR:
        case ENOTEMPTY:
        case ENOTDIR:
            return true;
        default:
            return false;
    }
}

void LogErrnoRemapEvent(const char* source, fuse_req_t req, uint32_t uid, int fromErr, int toErr) {
    if (!ShouldLogLimited(gErrnoRemapLogCount, 24)) {
        return;
    }
    __android_log_print(4, kLogTag, "errno remap source=%s req=%p unique=%lu uid=%u from=%d to=%d",
                        source, req, req ? (unsigned long)req->unique : 0UL,
                        static_cast<unsigned>(uid), fromErr, toErr);
}

}  // namespace

void ArmHiddenErrorRemap(fuse_req_t req, int err, const char* opName) {
    if (req == nullptr || err <= 0) {
        return;
    }
    gPendingHiddenErrReq = req;
    gPendingHiddenErrReqUnique = req->unique;
    gPendingHiddenErrno = err;
    const uint32_t uid = RuntimeState::ReqUid(req);
    if (uid != 0) {
        std::lock_guard<std::mutex> lock(gUidErrRemapMutex);
        UidErrRemapState& state = gUidErrRemapStates[uid];
        state.baselineErr = err;
        state.expiresAt = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        state.pendingCount = std::min<uint32_t>(state.pendingCount + 1, 8);
    }
}

void ArmHiddenCreateLeakRemap(fuse_req_t req, const char* opName) {
    if (req == nullptr) {
        return;
    }
    const uint32_t uid = RuntimeState::ReqUid(req);
    if (uid == 0 || !HiddenPathPolicy::IsTestHiddenUid(uid)) {
        return;
    }
    std::lock_guard<std::mutex> lock(gUidErrRemapMutex);
    UidErrRemapState& state = gUidErrRemapStates[uid];
    state.baselineErr = EPERM;
    state.expiresAt = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    state.pendingCount = std::min<uint32_t>(state.pendingCount + 1, 8);
}

int MaybeRewriteHiddenLeakErrno(fuse_req_t req, int err, const char* caller) {
    if (req != nullptr && gPendingHiddenErrReq == req &&
        gPendingHiddenErrReqUnique == req->unique && gPendingHiddenErrno > 0 && err > 0 &&
        IsExistenceLeakErrno(err)) {
        const int baselineErr = gPendingHiddenErrno;
        gPendingHiddenErrReq = nullptr;
        gPendingHiddenErrReqUnique = 0;
        gPendingHiddenErrno = 0;

        if (err != baselineErr) {
            LogErrnoRemapEvent("req", req, RuntimeState::ReqUid(req), err, baselineErr);
            return baselineErr;
        }
        return err;
    }

    if (req == nullptr || err <= 0 || !IsExistenceLeakErrno(err)) {
        return err;
    }

    const uint32_t uid = RuntimeState::ReqUid(req);
    if (uid == 0) {
        return err;
    }

    int uidBaselineErr = 0;
    {
        std::lock_guard<std::mutex> lock(gUidErrRemapMutex);
        const auto it = gUidErrRemapStates.find(uid);
        if (it != gUidErrRemapStates.end()) {
            if (it->second.expiresAt >= std::chrono::steady_clock::now() &&
                it->second.baselineErr > 0 && it->second.pendingCount > 0) {
                uidBaselineErr = it->second.baselineErr;
                it->second.pendingCount--;
            }
            if (it->second.pendingCount == 0 ||
                it->second.expiresAt < std::chrono::steady_clock::now()) {
                gUidErrRemapStates.erase(it);
            }
        }
    }

    if (uidBaselineErr > 0 && uidBaselineErr != err) {
        LogErrnoRemapEvent("uid", req, uid, err, uidBaselineErr);
        return uidBaselineErr;
    }
    return err;
}

extern "C" bool WrappedShouldNotCache(void* fuse, const std::string& path) {
    if (IsAnyHiddenSubtreePath(path)) {
        return true;
    }
    auto fn = reinterpret_cast<ShouldNotCacheFn>(gOriginalShouldNotCache);
    return fn ? fn(fuse, path) : false;
}

bool IsTrackedHiddenSubtreeInode(uint64_t ino) {
    std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
    return gHiddenSubtreeInodes.find(ino) != gHiddenSubtreeInodes.end();
}

bool TrackHiddenSubtreeInode(uint64_t ino) {
    if (ino == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
    return gHiddenSubtreeInodes.insert(ino).second;
}

bool RemoveTrackedHiddenSubtreeInode(uint64_t ino) {
    if (ino == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(gHiddenSubtreeInodesMutex);
    return gHiddenSubtreeInodes.erase(ino) != 0;
}

std::optional<std::string> LookupTrackedPathForInode(uint64_t ino) {
    if (ino == 0) {
        return std::nullopt;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (rootParent != 0 && ino == rootParent) {
        return std::string(kVisibleStorageRoots[0]);
    }
    std::lock_guard<std::mutex> lock(gInodePathCacheMutex);
    const auto it = gInodePathCache.find(ino);
    if (it == gInodePathCache.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<uint64_t> LookupTrackedInodeForPath(std::string_view path) {
    if (path.empty()) {
        return std::nullopt;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    if (rootParent != 0 && path == kVisibleStorageRoots[0]) {
        return rootParent;
    }
    std::lock_guard<std::mutex> lock(gInodePathCacheMutex);
    for (const auto& [ino, trackedPath] : gInodePathCache) {
        if (trackedPath == path) {
            return ino;
        }
    }
    return std::nullopt;
}

void RememberTrackedPathForInode(uint64_t ino, std::string_view path) {
    if (ino == 0 || path.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(gInodePathCacheMutex);
    gInodePathCache[ino] = std::string(path);
}

void RememberRecentHiddenParentPath(uint32_t uid, std::string_view path) {
    if (path.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(gRecentHiddenParentPathsMutex);
    gRecentHiddenParentPathAnyUid = std::string(path);
    gRecentHiddenParentPathAnyUidOwner = uid;
    if (uid != 0) {
        gRecentHiddenParentPaths[uid] = gRecentHiddenParentPathAnyUid;
        gRecentHiddenParentPathUids[uid] = uid;
    }
}

std::optional<std::string> LookupRecentHiddenParentPath(uint32_t uid, uint32_t* matchedHiddenUid) {
    std::lock_guard<std::mutex> lock(gRecentHiddenParentPathsMutex);
    if (uid != 0) {
        const auto it = gRecentHiddenParentPaths.find(uid);
        if (it != gRecentHiddenParentPaths.end()) {
            if (matchedHiddenUid != nullptr) {
                const auto uidIt = gRecentHiddenParentPathUids.find(uid);
                *matchedHiddenUid =
                    uidIt != gRecentHiddenParentPathUids.end() ? uidIt->second : uid;
            }
            return it->second;
        }
    }
    if (gRecentHiddenParentPathAnyUid.empty()) {
        return std::nullopt;
    }
    if (matchedHiddenUid != nullptr) {
        *matchedHiddenUid = gRecentHiddenParentPathAnyUidOwner;
    }
    return gRecentHiddenParentPathAnyUid;
}

void ClearRecentHiddenParentPath(uint32_t uid) {
    std::lock_guard<std::mutex> lock(gRecentHiddenParentPathsMutex);
    if (uid != 0) {
        gRecentHiddenParentPaths.erase(uid);
        gRecentHiddenParentPathUids.erase(uid);
    }
    if (uid == 0 || uid == gRecentHiddenParentPathAnyUidOwner) {
        gRecentHiddenParentPathAnyUid.clear();
        gRecentHiddenParentPathAnyUidOwner = 0;
    }
}

bool HiddenPathPolicy::IsConfiguredHiddenRootEntryName(std::string_view name) {
    const auto config = CurrentHideConfig();
    for (const auto& rootEntryName : config->hiddenRootEntryNames) {
        if (name == rootEntryName) {
            return true;
        }
    }

    if (!HasNonAsciiByte(name)) {
        return false;
    }

    std::string sanitized(name);
    if (!UnicodePolicy::NeedsSanitization(sanitized)) {
        return false;
    }
    UnicodePolicy::RewriteString(sanitized);

    for (const auto& rootEntryName : config->hiddenRootEntryNames) {
        if (sanitized == rootEntryName) {
            return true;
        }
    }
    return false;
}

bool HiddenPathPolicy::IsHiddenRootEntryName(std::string_view name) {
    return IsConfiguredHiddenRootEntryName(name) ||
           (CurrentHideConfig()->enableHideAllRootEntries && IsWildcardRootEntryCandidate(name));
}

bool HiddenPathPolicy::IsAnyHiddenSubtreePath(std::string_view path) {
    if (const auto relativePath = RelativePathForVisibleRoot(path);
        relativePath.has_value() && MatchesRelativeHiddenPathList(*relativePath, false)) {
        return true;
    }
    for (const auto& root : kVisibleStorageRoots) {
        if (path.size() <= root.size() || path.compare(0, root.size(), root) != 0 ||
            path[root.size()] != '/') {
            continue;
        }

        const size_t componentStart = root.size() + 1;
        const size_t slashPos = path.find('/', componentStart);
        const size_t componentEnd = slashPos == std::string_view::npos ? path.size() : slashPos;
        if (componentEnd <= componentStart) {
            continue;
        }

        const std::string_view rootEntry =
            path.substr(componentStart, componentEnd - componentStart);
        if (IsHiddenRootEntryName(rootEntry)) {
            return true;
        }
    }
    return false;
}

bool HiddenPathPolicy::IsExactHiddenTargetPath(std::string_view path) {
    if (const auto relativePath = RelativePathForVisibleRoot(path);
        relativePath.has_value() && MatchesRelativeHiddenPathList(*relativePath, true)) {
        return true;
    }
    for (const auto& root : kVisibleStorageRoots) {
        if (path.size() <= root.size() || path.compare(0, root.size(), root) != 0 ||
            path[root.size()] != '/') {
            continue;
        }

        const size_t componentStart = root.size() + 1;
        const size_t slashPos = path.find('/', componentStart);
        if (slashPos != std::string_view::npos) {
            continue;
        }

        const std::string_view rootEntry = path.substr(componentStart);
        if (IsHiddenRootEntryName(rootEntry)) {
            return true;
        }
    }
    return false;
}

bool HiddenPathPolicy::IsHiddenRootDirectoryPath(std::string_view path) {
    for (const auto& root : kVisibleStorageRoots) {
        if (path == root) {
            return true;
        }
    }
    return false;
}

bool IsParentOfExactHiddenTargetPath(std::string_view path) {
    for (const auto& root : kVisibleStorageRoots) {
        if (path == root) {
            const auto config = CurrentHideConfig();
            return !config->hiddenRootEntryNames.empty() || config->enableHideAllRootEntries;
        }
    }

    const auto relativePath = RelativePathForVisibleRoot(path);
    if (!relativePath.has_value()) {
        return false;
    }

    const auto config = CurrentHideConfig();
    for (const auto& hiddenRelativePath : config->hiddenRelativePaths) {
        const std::string normalized = NormalizeRelativeHiddenPath(hiddenRelativePath);
        if (normalized.empty()) {
            continue;
        }
        const size_t slash = normalized.rfind('/');
        if (slash == std::string::npos) {
            continue;
        }
        if (*relativePath == normalized.substr(0, slash)) {
            return true;
        }
    }
    return false;
}

std::string HiddenPathPolicy::JoinPathComponent(std::string_view parent, std::string_view child) {
    std::string joined(parent);
    if (joined.empty() || joined.back() != '/') {
        joined.push_back('/');
    }
    joined.append(child.data(), child.size());
    return joined;
}

size_t AlignDirentName(size_t nameLen) {
    return (nameLen + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1);
}

size_t FuseDirentRecordSize(const fuse_dirent* dirent) {
    return offsetof(fuse_dirent, name) + AlignDirentName(dirent->namelen);
}

size_t FuseDirentplusRecordSize(const fuse_dirent* dirent) {
    return kFuseEntryOutWireSize + offsetof(fuse_dirent, name) + AlignDirentName(dirent->namelen);
}

bool HiddenPathPolicy::ShouldFilterHiddenRootDirent(uint32_t uid, uint64_t ino,
                                                    std::string_view name,
                                                    bool requireParentMatch) {
    if (!IsTestHiddenUid(uid)) {
        return false;
    }

    if (const auto parentPath = LookupTrackedPathForInode(ino); parentPath.has_value()) {
        const std::string childPath = JoinPathComponent(*parentPath, name);
        if (IsExactHiddenTargetPath(childPath)) {
            return true;
        }
    }

    if (!IsHiddenRootEntryName(name)) {
        return false;
    }
    if (!requireParentMatch) {
        return true;
    }
    const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
    return rootParent == 0 || ino == rootParent;
}

bool ShouldFilterTrackedHiddenDirentInode(uint32_t uid, uint64_t childIno, std::string_view name) {
    if (!HiddenPathPolicy::IsTestHiddenUid(uid) || childIno == 0) {
        return false;
    }
    if (!IsTrackedHiddenSubtreeInode(childIno)) {
        return false;
    }
    return true;
}

bool ShouldFilterDirentForParentPath(uint32_t uid, std::string_view parentPath, uint64_t childIno,
                                     std::string_view name) {
    if (!HiddenPathPolicy::IsTestHiddenUid(uid)) {
        return false;
    }
    if (ShouldFilterTrackedHiddenDirentInode(uid, childIno, name)) {
        return true;
    }
    const std::string childPath = HiddenPathPolicy::JoinPathComponent(parentPath, name);
    return HiddenPathPolicy::IsExactHiddenTargetPath(childPath);
}

bool DirentFilter::BuildFilteredDirentPayload(const char* data, size_t size, uint32_t uid,
                                              uint64_t ino, std::vector<char>* out,
                                              size_t* removedCount, bool requireParentMatch) {
    if (data == nullptr || size == 0 || out == nullptr || removedCount == nullptr) {
        return false;
    }

    out->clear();
    out->reserve(size);
    size_t offset = 0;
    size_t removed = 0;
    while (offset + offsetof(fuse_dirent, name) <= size) {
        const auto* dirent = reinterpret_cast<const fuse_dirent*>(data + offset);
        const size_t recordSize = FuseDirentRecordSize(dirent);
        if (recordSize == 0 || offset + recordSize > size) {
            return false;
        }
        const std::string_view name(dirent->name, dirent->namelen);
        if (ShouldFilterTrackedHiddenDirentInode(uid, dirent->ino, name) ||
            ShouldFilterHiddenRootDirent(uid, ino, name, requireParentMatch)) {
            removed++;
        } else {
            out->insert(out->end(), data + offset, data + offset + recordSize);
        }
        offset += recordSize;
    }
    if (offset != size) {
        return false;
    }
    *removedCount = removed;
    return removed != 0;
}

bool BuildFilteredDirentPayloadForParentPath(const char* data, size_t size, uint32_t uid,
                                             std::string_view parentPath, std::vector<char>* out,
                                             size_t* removedCount,
                                             std::vector<FilteredDirentMatch>* removedEntries) {
    if (data == nullptr || size == 0 || out == nullptr || removedCount == nullptr ||
        parentPath.empty()) {
        return false;
    }

    out->clear();
    out->reserve(size);
    size_t offset = 0;
    size_t removed = 0;
    while (offset + offsetof(fuse_dirent, name) <= size) {
        const auto* dirent = reinterpret_cast<const fuse_dirent*>(data + offset);
        const size_t recordSize = FuseDirentRecordSize(dirent);
        if (recordSize == 0 || offset + recordSize > size) {
            return false;
        }
        const std::string_view name(dirent->name, dirent->namelen);
        if (ShouldFilterDirentForParentPath(uid, parentPath, dirent->ino, name)) {
            removed++;
            if (removedEntries != nullptr) {
                removedEntries->push_back(FilteredDirentMatch{std::string(name), dirent->ino});
            }
        } else {
            out->insert(out->end(), data + offset, data + offset + recordSize);
        }
        offset += recordSize;
    }
    if (offset != size) {
        return false;
    }
    *removedCount = removed;
    return removed != 0;
}

bool DirentFilter::BuildFilteredDirentplusPayload(const char* data, size_t size, uint32_t uid,
                                                  uint64_t ino, std::vector<char>* out,
                                                  size_t* removedCount, bool requireParentMatch) {
    if (data == nullptr || size == 0 || out == nullptr || removedCount == nullptr) {
        return false;
    }

    out->clear();
    out->reserve(size);
    size_t offset = 0;
    size_t removed = 0;
    while (offset + kFuseEntryOutWireSize + offsetof(fuse_dirent, name) <= size) {
        const auto* dirent =
            reinterpret_cast<const fuse_dirent*>(data + offset + kFuseEntryOutWireSize);
        const size_t recordSize = FuseDirentplusRecordSize(dirent);
        if (recordSize == 0 || offset + recordSize > size) {
            return false;
        }
        const std::string_view name(dirent->name, dirent->namelen);
        if (ShouldFilterTrackedHiddenDirentInode(uid, dirent->ino, name) ||
            ShouldFilterHiddenRootDirent(uid, ino, name, requireParentMatch)) {
            removed++;
        } else {
            out->insert(out->end(), data + offset, data + offset + recordSize);
        }
        offset += recordSize;
    }
    if (offset != size) {
        return false;
    }
    *removedCount = removed;
    return removed != 0;
}

bool BuildFilteredDirentplusPayloadForParentPath(const char* data, size_t size, uint32_t uid,
                                                 std::string_view parentPath,
                                                 std::vector<char>* out, size_t* removedCount,
                                                 std::vector<FilteredDirentMatch>* removedEntries) {
    if (data == nullptr || size == 0 || out == nullptr || removedCount == nullptr ||
        parentPath.empty()) {
        return false;
    }

    out->clear();
    out->reserve(size);
    size_t offset = 0;
    size_t removed = 0;
    while (offset + kFuseEntryOutWireSize + offsetof(fuse_dirent, name) <= size) {
        const auto* dirent =
            reinterpret_cast<const fuse_dirent*>(data + offset + kFuseEntryOutWireSize);
        const size_t recordSize = FuseDirentplusRecordSize(dirent);
        if (recordSize == 0 || offset + recordSize > size) {
            return false;
        }
        const std::string_view name(dirent->name, dirent->namelen);
        if (ShouldFilterDirentForParentPath(uid, parentPath, dirent->ino, name)) {
            removed++;
            if (removedEntries != nullptr) {
                removedEntries->push_back(FilteredDirentMatch{std::string(name), dirent->ino});
            }
        } else {
            out->insert(out->end(), data + offset, data + offset + recordSize);
        }
        offset += recordSize;
    }
    if (offset != size) {
        return false;
    }
    *removedCount = removed;
    return removed != 0;
}

void NoteHiddenSubtreePathForCache(std::string_view path) {
    if (!IsAnyHiddenSubtreePath(path)) {
        return;
    }

    RuntimeState::ScheduleHiddenEntryInvalidation();

    if (gInPfLookup && gCurrentLookupParentInode != 0) {
        const uint64_t rootParent = gHiddenRootParentInode.load(std::memory_order_relaxed);
        if (IsExactHiddenTargetPath(path) && gCurrentLookupParentInode == rootParent) {
            RemoveTrackedHiddenSubtreeInode(gCurrentLookupParentInode);
            return;
        }
        gTrackHiddenSubtreeLookup = true;
        if (TrackHiddenSubtreeInode(gCurrentLookupParentInode)) {
            RuntimeState::ScheduleHiddenInodeInvalidation(gCurrentLookupParentInode);
        }
    }

    if (gInPfGetattr && gPfGetattrIno != 0) {
        gZeroAttrCacheForCurrentGetattr = true;
        if (TrackHiddenSubtreeInode(gPfGetattrIno)) {
            RuntimeState::ScheduleHiddenInodeInvalidation(gPfGetattrIno);
        }
    }
}

bool HiddenPathPolicy::IsReadOnly(uint32_t uid, const std::string& path) {
    auto config = CurrentHideConfig();
    if (config->readOnlyRules.empty()) return false;
    bool isReadOnly = false;
    size_t bestMatchLen = 0;
    for (const auto& rule : config->readOnlyRules) {
        bool pkgMatch = false;
        if (rule.packageName == "*" || rule.packageName == "all") {
            pkgMatch = true;
        } else {
            pkgMatch = IsUidInPackage(uid, rule.packageName);
        }
        if (!pkgMatch) continue;

        if (fnmatch(rule.pattern.c_str(), path.c_str(), 0) == 0) {
            if (rule.pattern.length() > bestMatchLen) {
                bestMatchLen = rule.pattern.length();
                isReadOnly = true;
            }
        }
    }
    return isReadOnly;
}

std::string HiddenPathPolicy::GetRedirectTarget(uint32_t uid, const std::string& fusePath) {
    auto config = CurrentHideConfig();
    if (config->redirectRules.empty()) return fusePath;
    std::string target = fusePath;
    size_t bestMatchLen = 0;
    for (const auto& rule : config->redirectRules) {
        bool pkgMatch = false;
        if (rule.packageName == "*" || rule.packageName == "all") {
            pkgMatch = true;
        } else {
            pkgMatch = IsUidInPackage(uid, rule.packageName);
        }
        if (!pkgMatch) continue;

        if (fnmatch(rule.pattern.c_str(), fusePath.c_str(), 0) == 0) {
            if (rule.pattern.length() > bestMatchLen) {
                bestMatchLen = rule.pattern.length();
                if (rule.pattern.ends_with("/*")) {
                    std::string prefix = rule.pattern.substr(0, rule.pattern.length() - 2);
                    if (fusePath.starts_with(prefix)) {
                        std::string suffix = fusePath.substr(prefix.length());
                        target = rule.target + suffix;
                    } else {
                        target = rule.target;
                    }
                } else {
                    target = rule.target;
                }
            }
        }
    }
    return target;
}

bool IsConfiguredHiddenRootEntryName(std::string_view name) {
    return HiddenPathPolicy::IsConfiguredHiddenRootEntryName(name);
}

bool IsHiddenRootEntryName(std::string_view name) {
    return HiddenPathPolicy::IsHiddenRootEntryName(name);
}

bool IsAnyHiddenSubtreePath(std::string_view path) {
    return HiddenPathPolicy::IsAnyHiddenSubtreePath(path);
}

bool IsExactHiddenTargetPath(std::string_view path) {
    return HiddenPathPolicy::IsExactHiddenTargetPath(path);
}

bool IsHiddenRootDirectoryPath(std::string_view path) {
    return HiddenPathPolicy::IsHiddenRootDirectoryPath(path);
}

std::string JoinPathComponent(std::string_view parent, std::string_view child) {
    return HiddenPathPolicy::JoinPathComponent(parent, child);
}

bool ShouldFilterHiddenRootDirent(uint32_t uid, uint64_t ino, std::string_view name,
                                  bool requireParentMatch) {
    return HiddenPathPolicy::ShouldFilterHiddenRootDirent(uid, ino, name, requireParentMatch);
}

bool BuildFilteredDirentPayload(const char* data, size_t size, uint32_t uid, uint64_t ino,
                                std::vector<char>* out, size_t* removedCount,
                                bool requireParentMatch) {
    return DirentFilter::BuildFilteredDirentPayload(data, size, uid, ino, out, removedCount,
                                                    requireParentMatch);
}

bool BuildFilteredDirentplusPayload(const char* data, size_t size, uint32_t uid, uint64_t ino,
                                    std::vector<char>* out, size_t* removedCount,
                                    bool requireParentMatch) {
    return DirentFilter::BuildFilteredDirentplusPayload(data, size, uid, ino, out, removedCount,
                                                        requireParentMatch);
}

uint32_t ReqUid(fuse_req_t req) {
    return RuntimeState::ReqUid(req);
}

void RememberFuseSession(fuse_req_t req) {
    RuntimeState::RememberFuseSession(req);
}

void ScheduleHiddenEntryInvalidation() {
    RuntimeState::ScheduleHiddenEntryInvalidation();
}

void ScheduleHiddenInodeInvalidation(uint64_t ino) {
    RuntimeState::ScheduleHiddenInodeInvalidation(ino);
}

}  // namespace fusehide
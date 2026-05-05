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

// 使用 RAII 机制严格控制 UID 的生命周期，确保不会污染其他系统请求
class ScopedActiveUid final {
   public:
    explicit ScopedActiveUid(uint32_t uid) : previous_(gActiveUid) {
        gActiveUid = uid;
    }

    ~ScopedActiveUid() {
        gActiveUid = previous_;
    }

   private:
    uint32_t previous_;
};

bool ShouldHideLowerFsCreatePath(std::string_view pathView) {
    return gActiveUid != 0 && HiddenPathPolicy::IsTestHiddenUid(gActiveUid) &&
           HiddenPathPolicy::IsExactHiddenTargetPath(pathView);
}

bool ShouldHideLowerFsPath(std::string_view pathView) {
    return gActiveUid != 0 && HiddenPathPolicy::IsTestHiddenUid(gActiveUid) &&
           HiddenPathPolicy::ShouldHideTestPath(gActiveUid, pathView);
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
        DebugLogPrint(4,
                      "skip filtered child invalidation parent=%s names=%zu reason=no_parent_ino",
                      DebugPreview(parentPath).c_str(), removedEntries.size());
        return;
    }
    for (const auto& entry : removedEntries) {
        RuntimeState::ScheduleSpecificEntryInvalidation(*parentIno, entry.name);
        if (entry.ino != 0) {
            const std::string childPath =
                HiddenPathPolicy::JoinPathComponent(parentPath, entry.name);
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

// --- 路径重定向与只读规则 核心匹配逻辑 ---
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

bool HiddenPathPolicy::IsReadOnly(uint32_t uid, const std::string& path) {
    if (uid == 0 || path.empty()) return false;
    auto config = CurrentHideConfig();
    if (config->readOnlyRules.empty()) return false;

    auto pkgs = GetPackagesForUid(uid);
    if (pkgs.empty()) return false;

    for (const auto& rule : config->readOnlyRules) {
        bool pkgMatch = false;
        if (rule.packageName.empty() || rule.packageName == "*") {
            pkgMatch = true;
        } else {
            for (const auto& pkg : pkgs) {
                if (fnmatch(rule.packageName.c_str(), pkg.c_str(), 0) == 0) {
                    pkgMatch = true;
                    break;
                }
            }
        }
        if (!pkgMatch) continue;

        std::string pat = rule.pattern;
        bool hasWildcard = (pat.find('*') != std::string::npos || pat.find('?') != std::string::npos);

        if (hasWildcard) {
            if (pat.ends_with("/*") && path == pat.substr(0, pat.length() - 2)) return true;
            if (fnmatch(pat.c_str(), path.c_str(), FNM_PATHNAME) == 0) return true;
        } else {
            // 智能目录前缀匹配
            std::string dirPat = pat;
            if (!dirPat.ends_with('/')) dirPat += '/';

            if (path == pat || path + "/" == dirPat) return true; // 自身匹配
            if (path.starts_with(dirPat)) return true;            // 子文件匹配
        }
    }
    return false;
}

std::string HiddenPathPolicy::GetRedirectTarget(uint32_t uid, const std::string& fusePath) {
    if (uid == 0 || fusePath.empty()) return "";
    auto config = CurrentHideConfig();
    if (config->redirectRules.empty()) return "";

    auto pkgs = GetPackagesForUid(uid);
    if (pkgs.empty()) return "";

    for (const auto& rule : config->redirectRules) {
        bool pkgMatch = false;
        if (rule.packageName.empty() || rule.packageName == "*") {
            pkgMatch = true;
        } else {
            for (const auto& pkg : pkgs) {
                if (fnmatch(rule.packageName.c_str(), pkg.c_str(), 0) == 0) {
                    pkgMatch = true;
                    break;
                }
            }
        }
        if (!pkgMatch) continue;

        std::string pat = rule.pattern;
        std::string tar = rule.target;

        bool isWildcardPrefix = false;
        if (pat.ends_with("/*")) {
            pat = pat.substr(0, pat.length() - 2);
            isWildcardPrefix = true;
        } else if (pat.ends_with("*") && !pat.ends_with("\\*")) {
            pat = pat.substr(0, pat.length() - 1);
            isWildcardPrefix = true;
        }

        if (isWildcardPrefix || pat.find('*') == std::string::npos) {
            // 智能目录前缀匹配及替换
            std::string dirPat = pat;
            if (!dirPat.ends_with('/')) dirPat += '/';

            // 完全匹配目标文件夹本身
            if (fusePath == pat || fusePath + "/" == dirPat) {
                return tar;
            }
            // 匹配其子文件并替换前缀
            if (fusePath.starts_with(dirPat)) {
                std::string tail = fusePath.substr(dirPat.length());
                std::string res = tar;
                if (!res.ends_with('/')) res += '/';
                res += tail;
                return res;
            }
        } else {
            if (fnmatch(rule.pattern.c_str(), fusePath.c_str(), FNM_PATHNAME) == 0) {
                return tar;
            }
        }
    }
    return "";
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
// ----------------------------------------------------

extern "C" void WrappedPfLookup(fuse_req_t req, uint64_t parent, const char* name) {
    RuntimeState::RememberFuseSession(req);
    uint32_t uid = RuntimeState::ReqUid(req);
    if (name != nullptr && IsConfiguredHiddenRootEntryName(name) && parent != 0) {
        uint64_t expected = 0;
        if (gHiddenRootParentInode.compare_exchange_strong(expected, parent,
                                                           std::memory_order_relaxed)) {
            DebugLogPrint(4, "record hidden root parent=%s", InodePath(parent).c_str());
        }
    }
    gInPfLookup = true;
    gCurrentLookupParentInode = parent;
    gCurrentLookupName = name != nullptr ? std::string(name) : std::string();
    gTrackRootHiddenLookup = IsHiddenLookupCacheTarget(parent, name);
    gTrackHiddenSubtreeLookup = IsTrackedHiddenSubtreeInode(parent);
    DebugLogPrint(3, "lookup: req=%lu parent=%s name=%s", (unsigned long)req->unique,
                  InodePath(parent).c_str(), name ? DebugPreview(name).c_str() : "null");

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*)>(gOriginalPfLookup);
    if (fn) {
        ScopedActiveUid scopedUid(uid);
        fn(req, parent, name);
    }
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
                                     if (!entry) {
                                         return false;
                                     }
                                     const std::string& name = entry->d_name;
                                     if (name.empty() || name[0] == '/') {
                                         return false;
                                     }
                                     return HiddenPathPolicy::ShouldHideTestPath(
                                         uid,
                                         HiddenPathPolicy::JoinPathComponent(parentPath, name));
                                 }),
                  entries.end());

    if (entries.size() != before) {
        DebugLogPrint(4, "filter dir entries uid=%u parent=%s removed=%zu remaining=%zu",
                      static_cast<unsigned>(uid), DebugPreview(parentPath).c_str(),
                      before - entries.size(), entries.size());
    }
    return entries;
}

DirectoryEntries WrappedGetDirectoryEntries(void* wrapper, uint32_t uid, const std::string& path,
                                            DIR* dirp) {
    auto fn = reinterpret_cast<GetDirectoryEntriesFn>(gOriginalGetDirectoryEntries);
    ScopedActiveUid scopedUid(uid);
    DirectoryEntries entries = fn ? fn(wrapper, uid, path, dirp) : DirectoryEntries();
    if (gCurrentReaddirReqUnique != 0) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        auto it = gPendingReaddirContexts.find(gCurrentReaddirReqUnique);
        if (it != gPendingReaddirContexts.end()) {
            it->second.path = path;
            DebugLogPrint(4, "record readdir path req=%lu ino=%s path=%s",
                          (unsigned long)gCurrentReaddirReqUnique,
                          InodePath(it->second.ino).c_str(), DebugPreview(path).c_str());
        }
    }
    return FilterHiddenDirectoryEntries(uid, path, std::move(entries));
}

void WrappedAddDirectoryEntriesFromLowerFs(DIR* dirp, LowerFsDirentFilterFn filter,
                                           DirectoryEntries* entries) {
    auto fn =
        reinterpret_cast<AddDirectoryEntriesFromLowerFsFn>(gOriginalAddDirectoryEntriesFromLowerFs);
    if (fn == nullptr) {
        return;
    }
    fn(dirp, filter, entries);
    if (entries == nullptr || entries->empty()) {
        return;
    }

    const uint32_t uid = gActiveUid;
    if (uid == 0 || !HiddenPathPolicy::IsTestHiddenUid(uid)) {
        return;
    }

    std::string parentPath = ReadDirectoryPathFromDir(dirp);
    if (parentPath.empty()) {
        return;
    }

    const size_t before = entries->size();
    *entries = FilterHiddenDirectoryEntries(uid, parentPath, std::move(*entries));
    if (entries->size() != before) {
        DebugLogPrint(4, "filter lower-fs dir entries uid=%u parent=%s removed=%zu remaining=%zu",
                      static_cast<unsigned>(uid), DebugPreview(parentPath).c_str(),
                      before - entries->size(), entries->size());
    }
}

extern "C" void WrappedPfReaddirPostfilter(fuse_req_t req, uint64_t ino, uint32_t error_in,
                                           off_t off_in, off_t off_out, size_t size_out,
                                           const void* dirents_in, fuse_file_info* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, uint32_t, off_t, off_t, size_t,
                                        const void*, void*)>(gOriginalPfReaddirPostfilter);
    if (fn == nullptr) {
        return;
    }
    DebugLogPrint(3, "pf_readdir_postfilter uid=%u ino=%s err=%u off_in=%lld off_out=%lld size=%zu",
                  static_cast<unsigned>(uid), InodePath(ino).c_str(), error_in,
                  static_cast<long long>(off_in), static_cast<long long>(off_out), size_out);

    gInPfReaddirPostfilter = true;
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    {
        ScopedActiveUid scopedUid(uid);
        fn(req, ino, error_in, off_in, off_out, size_out, dirents_in, fi);
    }
    gCurrentReaddirReqUnique = 0;
    gInPfReaddirPostfilter = false;
}

extern "C" void WrappedPfLookupPostfilter(fuse_req_t req, uint64_t parent, uint32_t error_in,
                                          const char* name, struct fuse_entry_out* feo,
                                          struct fuse_entry_bpf_out* febo) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    DebugLogPrint(3, "pf_lookup_postfilter req=%p uid=%u parent=%s name=%s err_in=%u", req,
                  static_cast<unsigned>(uid), InodePath(parent).c_str(),
                  name ? DebugPreview(name).c_str() : "null", error_in);
    if (IsHiddenLookupTarget(uid, parent, error_in, name)) {
        DebugLogPrint(4, "pf_lookup_postfilter hide uid=%u parent=%s name=%s",
                      static_cast<unsigned>(uid), InodePath(parent).c_str(), name);
        RuntimeState::ScheduleHiddenEntryInvalidation();
        if (ReplyErrorBridge::Reply(req, ENOENT, "pf_lookup_postfilter").has_value()) {
            return;
        }
        ArmHiddenErrorRemap(req, ENOENT, "pf_lookup_postfilter");
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, uint32_t, const char*,
                                        struct fuse_entry_out*, struct fuse_entry_bpf_out*)>(
        gOriginalPfLookupPostfilter);
    if (fn) {
        gInPfLookupPostfilter = true;
        ScopedActiveUid scopedUid(uid);
        fn(req, parent, error_in, name, feo, febo);
        gInPfLookupPostfilter = false;
    }
}

extern "C" void WrappedPfAccess(fuse_req_t req, uint64_t ino, int mask) {
    RuntimeState::RememberFuseSession(req);
    uint32_t uid = RuntimeState::ReqUid(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, int)>(gOriginalPfAccess);
    if (fn) {
        ScopedActiveUid scopedUid(uid);
        fn(req, ino, mask);
    }
}

extern "C" void WrappedPfOpen(fuse_req_t req, uint64_t ino, fuse_file_info* fi) {
    RecordMonitorEventIno(req, "OPEN", ino);
    RuntimeState::RememberFuseSession(req);
    uint32_t uid = RuntimeState::ReqUid(req);
    
    if (fi != nullptr) {
        if (auto path = LookupTrackedPathForInode(ino)) {
            if (HiddenPathPolicy::IsReadOnly(uid, *path)) {
                int mode = fi->flags & O_ACCMODE;
                if (mode == O_WRONLY || mode == O_RDWR || (fi->flags & (O_CREAT | O_TRUNC | O_APPEND))) {
                    DebugLogPrint(4, "read-only policy applied for pf_open path=%s uid=%u", path->c_str(), uid);
                    fi->flags = (fi->flags & ~O_ACCMODE) | O_RDONLY;
                    fi->flags &= ~(O_CREAT | O_TRUNC | O_APPEND);
                }
            }
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, fuse_file_info*)>(gOriginalPfOpen);
    if (fn) {
        ScopedActiveUid scopedUid(uid);
        fn(req, ino, fi);
    }
}

extern "C" void WrappedPfOpendir(fuse_req_t req, uint64_t ino, fuse_file_info* fi) {
    RuntimeState::RememberFuseSession(req);
    uint32_t uid = RuntimeState::ReqUid(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, void*)>(gOriginalPfOpendir);
    if (fn) {
        ScopedActiveUid scopedUid(uid);
        fn(req, ino, fi);
    }
}

extern "C" void WrappedPfMkdir(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode) {
    RecordMonitorEvent(req, "CREATE", parent, name);
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    DebugLogPrint(4,
                  "create-trace pf_mkdir uid=%u parent=%s name=%s mode=%o hidden_root=%d "
                  "hidden_desc=%d",
                  static_cast<unsigned>(uid), InodePath(parent).c_str(),
                  name ? DebugPreview(name).c_str() : "null", mode,
                  kind == HiddenNamedTargetKind::Root ? 1 : 0,
                  kind == HiddenNamedTargetKind::Descendant ? 1 : 0);
    if (ReplyHiddenNamedTargetError(req, "pf_mkdir", kind, EACCES, ENOENT)) {
        return;
    }

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block mkdir path=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_mkdir").has_value()) return;
        }
    }

    auto fn =
        reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t)>(gOriginalPfMkdir);
    if (fn) {
        ScopedActiveUid scopedUid(uid);
        fn(req, parent, name, mode);
    }
}

extern "C" void WrappedPfMknod(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode,
                               uint64_t rdev) {
    RecordMonitorEvent(req, "CREATE", parent, name);
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    DebugLogPrint(4,
                  "create-trace pf_mknod uid=%u parent=%s name=%s mode=%o rdev=%llu hidden_root=%d "
                  "hidden_desc=%d",
                  static_cast<unsigned>(uid), InodePath(parent).c_str(),
                  name ? DebugPreview(name).c_str() : "null", mode,
                  static_cast<unsigned long long>(rdev),
                  kind == HiddenNamedTargetKind::Root ? 1 : 0,
                  kind == HiddenNamedTargetKind::Descendant ? 1 : 0);
    if (ReplyHiddenNamedTargetError(req, "pf_mknod", kind, EPERM, ENOENT)) {
        return;
    }

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block mknod path=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_mknod").has_value()) return;
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t, uint64_t)>(
        gOriginalPfMknod);
    if (fn) {
        ScopedActiveUid scopedUid(uid);
        fn(req, parent, name, mode, rdev);
    }
}

extern "C" void WrappedPfUnlink(fuse_req_t req, uint64_t parent, const char* name) {
    RecordMonitorEvent(req, "DELETE", parent, name);
    RuntimeState::RememberFuseSession(req);
    uint32_t uid = RuntimeState::ReqUid(req);
    const HiddenNamedTargetKind kind =
        ClassifyHiddenNamedTarget(uid, parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_unlink", kind, ENOENT, ENOENT)) {
        return;
    }

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block unlink path=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_unlink").has_value()) return;
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*)>(gOriginalPfUnlink);
    if (fn) {
        ScopedActiveUid scopedUid(uid);
        fn(req, parent, name);
    }
}

extern "C" void WrappedPfRmdir(fuse_req_t req, uint64_t parent, const char* name) {
    RecordMonitorEvent(req, "DELETE", parent, name);
    RuntimeState::RememberFuseSession(req);
    uint32_t uid = RuntimeState::ReqUid(req);
    const HiddenNamedTargetKind kind =
        ClassifyHiddenNamedTarget(uid, parent, name);
    if (ReplyHiddenNamedTargetError(req, "pf_rmdir", kind, ENOENT, ENOENT)) {
        return;
    }

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block rmdir path=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_rmdir").has_value()) return;
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*)>(gOriginalPfRmdir);
    if (fn) {
        ScopedActiveUid scopedUid(uid);
        fn(req, parent, name);
    }
}

extern "C" void WrappedPfRename(fuse_req_t req, uint64_t parent, const char* name,
                                uint64_t new_parent, const char* new_name, uint32_t flags) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    const HiddenNamedTargetKind srcKind = ClassifyHiddenNamedTarget(uid, parent, name);
    const HiddenNamedTargetKind dstKind = ClassifyHiddenNamedTarget(uid, new_parent, new_name);
    if (srcKind != HiddenNamedTargetKind::None || dstKind != HiddenNamedTargetKind::None) {
        DebugLogPrint(4,
                      "pf_rename hide named target src_root=%d src_desc=%d dst_root=%d dst_desc=%d "
                      "flags=0x%x",
                      srcKind == HiddenNamedTargetKind::Root ? 1 : 0,
                      srcKind == HiddenNamedTargetKind::Descendant ? 1 : 0,
                      dstKind == HiddenNamedTargetKind::Root ? 1 : 0,
                      dstKind == HiddenNamedTargetKind::Descendant ? 1 : 0, flags);
        RuntimeState::ScheduleHiddenEntryInvalidation();
        if (ReplyErrorBridge::Reply(req, ENOENT, "pf_rename").has_value()) {
            return;
        }
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

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint64_t, const char*,
                                        uint32_t)>(gOriginalPfRename);
    if (fn) {
        ScopedActiveUid scopedUid(uid);
        fn(req, parent, name, new_parent, new_name, flags);
    }
}

extern "C" void WrappedPfCreate(fuse_req_t req, uint64_t parent, const char* name, uint32_t mode,
                                fuse_file_info* fi) {
    RecordMonitorEvent(req, "CREATE", parent, name);
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    const HiddenNamedTargetKind kind = ClassifyHiddenNamedTarget(uid, parent, name);
    DebugLogPrint(4,
                  "create-trace pf_create uid=%u parent=%s name=%s mode=%o fi=%p hidden_root=%d "
                  "hidden_desc=%d",
                  static_cast<unsigned>(uid), InodePath(parent).c_str(),
                  name ? DebugPreview(name).c_str() : "null", mode, (void*)fi,
                  kind == HiddenNamedTargetKind::Root ? 1 : 0,
                  kind == HiddenNamedTargetKind::Descendant ? 1 : 0);
    if (ReplyHiddenNamedTargetError(req, "pf_create", kind, EPERM, ENOENT)) {
        return;
    }

    if (auto parentPath = LookupTrackedPathForInode(parent)) {
        std::string childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, name ? name : "");
        if (HiddenPathPolicy::IsReadOnly(uid, childPath)) {
            DebugLogPrint(4, "read-only block create path=%s", childPath.c_str());
            if (ReplyErrorBridge::Reply(req, EROFS, "pf_create").has_value()) return;
        }
    }

    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, const char*, uint32_t, fuse_file_info*)>(
        gOriginalPfCreate);
    if (fn) {
        ScopedActiveUid scopedUid(uid);
        fn(req, parent, name, mode, fi);
    }
}

extern "C" void WrappedPfReaddir(fuse_req_t req, uint64_t ino, size_t size, off_t off, fuse_file_info* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    auto fn =
        reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*)>(gOriginalPfReaddir);
    if (fn == nullptr) {
        return;
    }
    DebugLogPrint(3, "pf_readdir uid=%u ino=%s size=%zu off=%lld", static_cast<unsigned>(uid),
                  InodePath(ino).c_str(), size, static_cast<long long>(off));
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts[req->unique] = PendingReaddirContext{uid, ino, {}};
    }
    gInPfReaddir = true;
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    {
        ScopedActiveUid scopedUid(uid);
        fn(req, ino, size, off, fi);
    }
    gCurrentReaddirReqUnique = 0;
    gInPfReaddir = false;
}

extern "C" void WrappedDoReaddirCommon(fuse_req_t req, uint64_t ino, size_t size, off_t off,
                                       fuse_file_info* fi, bool plus) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*, bool)>(
        gOriginalDoReaddirCommon);
    if (fn == nullptr) {
        return;
    }
    DebugLogPrint(3, "do_readdir_common uid=%u ino=%s size=%zu off=%lld plus=%d",
                  static_cast<unsigned>(uid), InodePath(ino).c_str(), size,
                  static_cast<long long>(off), plus ? 1 : 0);
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts[req->unique] = PendingReaddirContext{uid, ino, {}};
    }
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    {
        ScopedActiveUid scopedUid(uid);
        fn(req, ino, size, off, fi, plus);
    }
    gCurrentReaddirReqUnique = 0;
}

extern "C" void WrappedPfReaddirplus(fuse_req_t req, uint64_t ino, size_t size, off_t off,
                                     fuse_file_info* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, size_t, off_t, void*)>(
        gOriginalPfReaddirplus);
    if (fn == nullptr) {
        return;
    }
    DebugLogPrint(3, "pf_readdirplus uid=%u ino=%s size=%zu off=%lld", static_cast<unsigned>(uid),
                  InodePath(ino).c_str(), size, static_cast<long long>(off));
    if (req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts[req->unique] = PendingReaddirContext{uid, ino, {}};
    }
    gInPfReaddirplus = true;
    gCurrentReaddirReqUnique = req != nullptr ? req->unique : 0;
    {
        ScopedActiveUid scopedUid(uid);
        fn(req, ino, size, off, fi);
    }
    gCurrentReaddirReqUnique = 0;
    gInPfReaddirplus = false;
}

extern "C" int WrappedNotifyInvalEntry(void* se, uint64_t parent, const char* name,
                                       size_t namelen) {
    auto fn =
        reinterpret_cast<int (*)(void*, uint64_t, const char*, size_t)>(gOriginalNotifyInvalEntry);
    int ret = fn ? fn(se, parent, name, namelen) : -1;
    DebugLogPrint(3, "notify_inval_entry: ino=0x%lx name=%s ret=%d", (unsigned long)parent,
                  name ? DebugPreview(std::string_view(name, namelen)).c_str() : "null", ret);
    return ret;
}

extern "C" int WrappedNotifyInvalInode(void* se, uint64_t ino, off_t off, off_t len) {
    auto fn = reinterpret_cast<int (*)(void*, uint64_t, off_t, off_t)>(gOriginalNotifyInvalInode);
    int ret = fn ? fn(se, ino, off, len) : -1;
    DebugLogPrint(3, "notify_inval_inode: ino=0x%lx name=%s ret=%d", (unsigned long)ino,
                  ino == 1 ? "(ROOT)" : "", ret);
    return ret;
}

extern "C" int WrappedReplyEntry(fuse_req_t req, const struct fuse_entry_param* e) {
    auto fn =
        reinterpret_cast<int (*)(fuse_req_t, const struct fuse_entry_param*)>(gOriginalReplyEntry);
    const bool hiddenLookupForUid = HiddenPathPolicy::IsTestHiddenUid(RuntimeState::ReqUid(req)) &&
                                    (gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup);
    if (hiddenLookupForUid) {
        if (gTrackRootHiddenLookup || gTrackHiddenSubtreeLookup) {
            ArmHiddenCreateLeakRemap(req, "fuse_reply_entry");
        }
        if (gTrackHiddenSubtreeLookup) {
            if (const auto parentPath = LookupTrackedPathForInode(gCurrentLookupParentInode);
                parentPath.has_value()) {
                RememberTrackedPathForInode(gCurrentLookupParentInode, *parentPath);
                RememberRecentHiddenParentPath(RuntimeState::ReqUid(req), *parentPath);
                DebugLogPrint(4, "refresh recent hidden parent from hidden lookup uid=%u path=%s",
                              static_cast<unsigned>(RuntimeState::ReqUid(req)),
                              DebugPreview(*parentPath).c_str());
                RuntimeState::ScheduleHiddenInodeInvalidation(gCurrentLookupParentInode);
            }
        }
        if (auto ret = ReplyErrorBridge::Reply(req, ENOENT, "fuse_reply_entry"); ret.has_value()) {
            DebugLogPrint(4, "hide lookup entry uid=%u req=%lu ino=%s root=%d child=%d ret=%d",
                          static_cast<unsigned>(RuntimeState::ReqUid(req)),
                          req ? (unsigned long)req->unique : 0UL,
                          e != nullptr ? InodePath(e->ino).c_str() : "(null)",
                          gTrackRootHiddenLookup ? 1 : 0, gTrackHiddenSubtreeLookup ? 1 : 0, *ret);
            RuntimeState::ScheduleHiddenEntryInvalidation();
            if (gCurrentLookupParentInode != 0 && !gCurrentLookupName.empty()) {
                RuntimeState::ScheduleSpecificEntryInvalidation(gCurrentLookupParentInode,
                                                                gCurrentLookupName);
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
        DebugLogPrint(4, "disable entry cache req=%lu ino=%s root=%d child=%d",
                      req ? (unsigned long)req->unique : 0UL, InodePath(e->ino).c_str(),
                      gTrackRootHiddenLookup ? 1 : 0, gTrackHiddenSubtreeLookup ? 1 : 0);
        RuntimeState::ScheduleHiddenEntryInvalidation();
        if (TrackHiddenSubtreeInode(e->ino)) {
            RuntimeState::ScheduleHiddenInodeInvalidation(e->ino);
        }
    }
    if (e != nullptr && gCurrentLookupParentInode != 0 && !gCurrentLookupName.empty()) {
        std::optional<std::string> childPath;
        if (const auto parentPath = LookupTrackedPathForInode(gCurrentLookupParentInode);
            parentPath.has_value()) {
            childPath = HiddenPathPolicy::JoinPathComponent(*parentPath, gCurrentLookupName);
        } else if (IsFirstComponentOfHiddenRelativePath(gCurrentLookupName)) {
            childPath =
                HiddenPathPolicy::JoinPathComponent(kVisibleStorageRoots[0], gCurrentLookupName);
            DebugLogPrint(4, "infer root child path ino=%s name=%s path=%s",
                          InodePath(gCurrentLookupParentInode).c_str(),
                          DebugPreview(gCurrentLookupName).c_str(),
                          DebugPreview(*childPath).c_str());
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
                RuntimeState::ScheduleSpecificEntryInvalidation(gCurrentLookupParentInode,
                                                                gCurrentLookupName);
                RuntimeState::ScheduleHiddenInodeInvalidation(e->ino);
                DebugLogPrint(4, "force uncached exact hidden target uid=%u path=%s ino=%s",
                              static_cast<unsigned>(RuntimeState::ReqUid(req)),
                              DebugPreview(*childPath).c_str(), InodePath(e->ino).c_str());
            }
            if (IsParentOfExactHiddenTargetPath(*childPath)) {
                RememberRecentHiddenParentPath(RuntimeState::ReqUid(req), *childPath);
                DebugLogPrint(4, "remember recent hidden parent uid=%u path=%s",
                              static_cast<unsigned>(RuntimeState::ReqUid(req)),
                              DebugPreview(*childPath).c_str());
            }
        }
    }
    if (e != nullptr && forceUncachedReplyEntry && replyEntry == e) {
        patchedEntry = *e;
        patchedEntry.entry_timeout = 0.0;
        patchedEntry.attr_timeout = 0.0;
        replyEntry = &patchedEntry;
        DebugLogPrint(4, "disable entry cache req=%lu ino=%s root=%d child=%d exact=%d",
                      req ? (unsigned long)req->unique : 0UL, InodePath(e->ino).c_str(),
                      gTrackRootHiddenLookup ? 1 : 0, gTrackHiddenSubtreeLookup ? 1 : 0,
                      exactHiddenTargetReplyEntry ? 1 : 0);
    }
    int ret = fn ? fn(req, replyEntry) : -1;
    DebugLogPrint(3,
                  "fuse_reply_entry: req=%lu ino=%s timeout=%.2le attr_timeout=%.2le bpf_fd=%lu "
                  "bpf_action=%lu backing_action=%lu backing_fd=%lu ret=%d",
                  (unsigned long)req->unique, InodePath(replyEntry->ino).c_str(),
                  replyEntry->entry_timeout, replyEntry->attr_timeout,
                  (unsigned long)replyEntry->bpf_fd, (unsigned long)replyEntry->bpf_action,
                  (unsigned long)replyEntry->backing_action, (unsigned long)replyEntry->backing_fd,
                  ret);
    return ret;
}

extern "C" int WrappedReplyAttr(fuse_req_t req, const struct stat* attr, double timeout) {
    auto fn = reinterpret_cast<int (*)(fuse_req_t, const struct stat*, double)>(gOriginalReplyAttr);
    const double replyTimeout = gZeroAttrCacheForCurrentGetattr ? 0.0 : timeout;
    if (gZeroAttrCacheForCurrentGetattr) {
        DebugLogPrint(4, "disable attr cache req=%p timeout=%.2le", req, replyTimeout);
    }
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
    const uint32_t requestFilterUid = gActiveUid != 0 ? gActiveUid : (hasPendingContext && pendingContext.uid != 0 ? pendingContext.uid : reqUid);
    const uint64_t filterIno = hasPendingContext ? pendingContext.ino : 0;
    
    const bool filterPlainReaddir = gInPfReaddir;
    const bool filterPostfilterReaddir = gInPfReaddirPostfilter;
    const bool filterReaddirplus = gInPfReaddirplus;
    const bool requireParentMatch = filterIno != 0;
    const char* filterMode = nullptr;
    uint32_t fallbackHiddenUid = 0;
    const std::optional<std::string> fallbackParentPath =
        filterIno == 0 ? LookupRecentHiddenParentPath(requestFilterUid, &fallbackHiddenUid)
                       : std::nullopt;
    const bool canBorrowFallbackUid =
        requestFilterUid == 0 && HiddenPathPolicy::IsTestHiddenUid(fallbackHiddenUid);
    const uint32_t filterUid = HiddenPathPolicy::IsTestHiddenUid(requestFilterUid)
                                   ? requestFilterUid
                                   : (canBorrowFallbackUid ? fallbackHiddenUid : 0);

    if (filterIno != 0 && !pendingContext.path.empty()) {
        RememberTrackedPathForInode(filterIno, pendingContext.path);
    }

    if (HiddenPathPolicy::IsTestHiddenUid(filterUid)) {
        DebugLogPrint(
            4,
            "reply_buf filter ctx req=%lu req_uid=%u uid=%u ino=%s pending=%d pending_path=%s "
            "fallback_parent=%s fallback_uid=%u mode_flags=%d/%d/%d",
            req ? (unsigned long)req->unique : 0UL, static_cast<unsigned>(requestFilterUid),
            static_cast<unsigned>(filterUid), InodePath(filterIno).c_str(),
            hasPendingContext ? 1 : 0,
            pendingContext.path.empty() ? "" : DebugPreview(pendingContext.path).c_str(),
            fallbackParentPath.has_value() ? DebugPreview(*fallbackParentPath).c_str() : "",
            static_cast<unsigned>(fallbackHiddenUid), filterPlainReaddir ? 1 : 0,
            filterReaddirplus ? 1 : 0, filterPostfilterReaddir ? 1 : 0);
    }

    if (HiddenPathPolicy::IsTestHiddenUid(filterUid)) {
        if (filterPlainReaddir) {
            if (DirentFilter::BuildFilteredDirentPayload(buf, size, filterUid, filterIno,
                                                         &filteredStorage, &removedCount,
                                                         requireParentMatch)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "readdir";
            }
        } else if (filterReaddirplus) {
            if (DirentFilter::BuildFilteredDirentplusPayload(buf, size, filterUid, filterIno,
                                                             &filteredStorage, &removedCount,
                                                             requireParentMatch)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "readdirplus";
            }
        } else if (filterPostfilterReaddir && size >= sizeof(fuse_read_out)) {
            const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
            const size_t payloadSize =
                std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
            std::vector<char> filteredPayload;
            if (DirentFilter::BuildFilteredDirentPayload(buf + sizeof(fuse_read_out), payloadSize,
                                                         filterUid, filterIno, &filteredPayload,
                                                         &removedCount, requireParentMatch)) {
                fuse_read_out patched = *readOut;
                patched.size = static_cast<uint32_t>(filteredPayload.size());
                filteredStorage.resize(sizeof(patched) + filteredPayload.size());
                std::memcpy(filteredStorage.data(), &patched, sizeof(patched));
                std::memcpy(filteredStorage.data() + sizeof(patched), filteredPayload.data(),
                            filteredPayload.size());
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "readdir_postfilter";
            }
        }

        if (filterMode == nullptr) {
            if (fallbackParentPath.has_value() &&
                BuildFilteredDirentplusPayloadForParentPath(buf, size, filterUid,
                                                            *fallbackParentPath, &filteredStorage,
                                                            &removedCount, &removedEntries)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "fallback_parent_direntplus";
                InvalidateFilteredParentChildren(*fallbackParentPath, removedEntries);
                ClearRecentHiddenParentPath(filterUid);
            } else if (fallbackParentPath.has_value() &&
                       BuildFilteredDirentPayloadForParentPath(
                           buf, size, filterUid, *fallbackParentPath, &filteredStorage,
                           &removedCount, &removedEntries)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "fallback_parent_dirent";
                InvalidateFilteredParentChildren(*fallbackParentPath, removedEntries);
                ClearRecentHiddenParentPath(filterUid);
            } else if (size >= sizeof(fuse_read_out) && fallbackParentPath.has_value()) {
                const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
                const size_t payloadSize =
                    std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
                std::vector<char> filteredPayload;
                if (BuildFilteredDirentPayloadForParentPath(
                        buf + sizeof(fuse_read_out), payloadSize, filterUid, *fallbackParentPath,
                        &filteredPayload, &removedCount, &removedEntries)) {
                    fuse_read_out patched = *readOut;
                    patched.size = static_cast<uint32_t>(filteredPayload.size());
                    filteredStorage.resize(sizeof(patched) + filteredPayload.size());
                    std::memcpy(filteredStorage.data(), &patched, sizeof(patched));
                    std::memcpy(filteredStorage.data() + sizeof(patched), filteredPayload.data(),
                                filteredPayload.size());
                    replyBuf = filteredStorage.data();
                    replySize = filteredStorage.size();
                    filterMode = "fallback_parent_read_out_dirent";
                    InvalidateFilteredParentChildren(*fallbackParentPath, removedEntries);
                    ClearRecentHiddenParentPath(filterUid);
                }
            }
        }

        if (filterMode == nullptr) {
            if (DirentFilter::BuildFilteredDirentplusPayload(
                    buf, size, filterUid, 0, &filteredStorage, &removedCount, false)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "auto_direntplus";
            } else if (DirentFilter::BuildFilteredDirentPayload(
                           buf, size, filterUid, 0, &filteredStorage, &removedCount, false)) {
                replyBuf = filteredStorage.data();
                replySize = filteredStorage.size();
                filterMode = "auto_dirent";
            } else if (size >= sizeof(fuse_read_out)) {
                const auto* readOut = reinterpret_cast<const fuse_read_out*>(buf);
                const size_t payloadSize =
                    std::min<size_t>(readOut->size, size - sizeof(fuse_read_out));
                std::vector<char> filteredPayload;
                if (DirentFilter::BuildFilteredDirentPayload(
                        buf + sizeof(fuse_read_out), payloadSize, filterUid, 0, &filteredPayload,
                        &removedCount, false)) {
                    fuse_read_out patched = *readOut;
                    patched.size = static_cast<uint32_t>(filteredPayload.size());
                    filteredStorage.resize(sizeof(patched) + filteredPayload.size());
                    std::memcpy(filteredStorage.data(), &patched, sizeof(patched));
                    std::memcpy(filteredStorage.data() + sizeof(patched), filteredPayload.data(),
                                filteredPayload.size());
                    replyBuf = filteredStorage.data();
                    replySize = filteredStorage.size();
                    filterMode = "auto_read_out_dirent";
                }
            }
        }
    }

    int ret = fn ? fn(req, replyBuf, replySize) : -1;
    if (hasPendingContext && req != nullptr) {
        std::lock_guard<std::mutex> lock(gPendingReaddirContextsMutex);
        gPendingReaddirContexts.erase(req->unique);
    }
    if (removedCount != 0) {
        DebugLogPrint(4, "filtered readdir reply mode=%s uid=%u ino=%s removed=%zu size=%zu->%zu",
                      filterMode ? filterMode : "unknown", static_cast<unsigned>(filterUid),
                      InodePath(filterIno).c_str(), removedCount, size, replySize);
    }
    if (gInPfLookupPostfilter) {
        DebugLogPrint(3, "pf_lookup_postfilter fuse_reply_buf req=%p", req);
    } else {
        DebugLogPrint(3, "fuse_reply_buf: req=%lu size=%zu ret=%d", (unsigned long)req->unique,
                      replySize, ret);
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
    if (gInPfLookupPostfilter) {
        DebugLogPrint(3, "pf_lookup_postfilter fuse_reply_err req=%p %d", req, err);
    } else {
        DebugLogPrint(3, "fuse_reply_err: req=%p err=%d ret=%d", req, err, ret);
    }
    return ret;
}

extern "C" void WrappedPfGetattr(fuse_req_t req, uint64_t ino, fuse_file_info* fi) {
    RuntimeState::RememberFuseSession(req);
    const uint32_t uid = RuntimeState::ReqUid(req);
    gZeroAttrCacheForCurrentGetattr = IsTrackedHiddenSubtreeInode(ino);
    if (HiddenPathPolicy::IsTestHiddenUid(uid)) {
        DebugLogPrint(4, "pf_getattr test uid=%u ino=0x%lx", static_cast<unsigned>(uid),
                      (unsigned long)ino);
    }
    auto fn = reinterpret_cast<void (*)(fuse_req_t, uint64_t, void*)>(gOriginalPfGetattr);
    if (fn) {
        gInPfGetattr = true;
        gPfGetattrIno = ino;
        ScopedActiveUid scopedUid(uid);
        fn(req, ino, fi);
        gPfGetattrIno = 0;
        gInPfGetattr = false;
        gZeroAttrCacheForCurrentGetattr = false;
    }
}

extern "C" int WrappedLstat(const char* path, struct stat* st) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();

    if (gInPfGetattr && gPfGetattrIno != 0 && HiddenPathPolicy::IsHiddenRootDirectoryPath(pathView)) {
        uint64_t expected = 0;
        const bool recorded = gHiddenRootParentInode.compare_exchange_strong(
            expected, gPfGetattrIno, std::memory_order_relaxed);
        if (recorded) {
            DebugLogPrint(4, "record hidden root parent from getattr=%s path=%s",
                          InodePath(gPfGetattrIno).c_str(), DebugPreview(pathView).c_str());
        }
        RemoveTrackedHiddenSubtreeInode(gPfGetattrIno);
        if (recorded && CurrentHideConfig()->enableHideAllRootEntries) {
            RuntimeState::ScheduleHiddenEntryInvalidation();
        }
    }
    NoteHiddenSubtreePathForCache(pathView);

    if (gActiveUid == 0) {
        auto fn = reinterpret_cast<int (*)(const char*, struct stat*)>(gOriginalLstat);
        int ret = fn ? fn(path, st) : -1;
        if (ret == 0 && gInPfGetattr && gPfGetattrIno != 0) {
            RememberTrackedPathForInode(gPfGetattrIno, pathView);
        }
        return ret;
    }

    if (HiddenPathPolicy::IsTestHiddenUid(gActiveUid)) {
        DebugLogPrint(4, "pf_getattr lstat uid=%u path=%s", static_cast<unsigned>(gActiveUid),
                      DebugPreview(pathView).c_str());
        if (HiddenPathPolicy::ShouldHideTestPath(gActiveUid, pathView)) {
            DebugLogPrint(4, "hide test lstat uid=%u path=%s", static_cast<unsigned>(gActiveUid),
                          DebugPreview(pathView).c_str());
            errno = ENOENT;
            return -1;
        }
    }

    std::string actualPath = path != nullptr ? ProcessRedirectPath(path, gActiveUid) : "";
    const char* targetPath = path != nullptr ? actualPath.c_str() : nullptr;

    auto fn = reinterpret_cast<int (*)(const char*, struct stat*)>(gOriginalLstat);
    if (fn) {
        const int ret = fn(targetPath, st);
        if (ret == 0 && gInPfGetattr && gPfGetattrIno != 0) {
            RememberTrackedPathForInode(gPfGetattrIno, pathView);
            if (HiddenPathPolicy::IsTestHiddenUid(gActiveUid) &&
                IsParentOfExactHiddenTargetPath(pathView)) {
                RememberRecentHiddenParentPath(gActiveUid, pathView);
                DebugLogPrint(4, "remember recent hidden parent from getattr uid=%u path=%s",
                              static_cast<unsigned>(gActiveUid), DebugPreview(pathView).c_str());
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

    if (gActiveUid == 0) {
        auto fn = reinterpret_cast<int (*)(const char*, struct stat*)>(gOriginalStat);
        return fn ? fn(path, st) : -1;
    }

    if (gInPfReaddirPostfilter && HiddenPathPolicy::IsTestHiddenUid(gActiveUid) &&
        HiddenPathPolicy::IsAnyHiddenSubtreePath(pathView)) {
        DebugLogPrint(4, "hide readdir stat uid=%u path=%s", static_cast<unsigned>(gActiveUid),
                      DebugPreview(pathView).c_str());
        errno = ENOENT;
        return -1;
    }

    std::string actualPath = path != nullptr ? ProcessRedirectPath(path, gActiveUid) : "";
    const char* targetPath = path != nullptr ? actualPath.c_str() : nullptr;

    auto fn = reinterpret_cast<int (*)(const char*, struct stat*)>(gOriginalStat);
    if (fn) {
        return fn(targetPath, st);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" ssize_t WrappedGetxattr(const char* path, const char* name, void* value, size_t size) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    
    if (gActiveUid == 0) {
        auto fn = reinterpret_cast<ssize_t (*)(const char*, const char*, void*, size_t)>(gOriginalGetxattr);
        return fn ? fn(path, name, value, size) : -1;
    }

    if (ShouldHideLowerFsPath(pathView)) {
        DebugLogPrint(4, "hide getxattr path=%s name=%s", DebugPreview(pathView).c_str(),
                      name != nullptr ? DebugPreview(name).c_str() : "null");
        errno = ENOENT;
        return -1;
    }

    std::string actualPath = path != nullptr ? ProcessRedirectPath(path, gActiveUid) : "";
    const char* targetPath = path != nullptr ? actualPath.c_str() : nullptr;

    auto fn = reinterpret_cast<ssize_t (*)(const char*, const char*, void*, size_t)>(gOriginalGetxattr);
    if (fn) {
        return fn(targetPath, name, value, size);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" ssize_t WrappedLgetxattr(const char* path, const char* name, void* value, size_t size) {
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();

    if (gActiveUid == 0) {
        auto fn = reinterpret_cast<ssize_t (*)(const char*, const char*, void*, size_t)>(gOriginalLgetxattr);
        return fn ? fn(path, name, value, size) : -1;
    }

    if (ShouldHideLowerFsPath(pathView)) {
        DebugLogPrint(4, "hide lgetxattr path=%s name=%s", DebugPreview(pathView).c_str(),
                      name != nullptr ? DebugPreview(name).c_str() : "null");
        errno = ENOENT;
        return -1;
    }

    std::string actualPath = path != nullptr ? ProcessRedirectPath(path, gActiveUid) : "";
    const char* targetPath = path != nullptr ? actualPath.c_str() : nullptr;

    auto fn = reinterpret_cast<ssize_t (*)(const char*, const char*, void*, size_t)>(gOriginalLgetxattr);
    if (fn) {
        return fn(targetPath, name, value, size);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedMkdirLibc(const char* path, mode_t mode) {
    const uint32_t uid = gActiveUid;
    if (uid == 0) {
        auto fn = reinterpret_cast<int (*)(const char*, mode_t)>(gOriginalMkdir);
        return fn ? fn(path, mode) : -1;
    }

    RecordMonitorEventPath(uid, "CREATE", path);
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    const bool hidden = ShouldHideLowerFsCreatePath(pathView);
    DebugLogPrint(4, "create-trace lower_mkdir uid=%u path=%s mode=%o hidden=%d",
                  static_cast<unsigned>(uid), DebugPreview(pathView).c_str(), mode, hidden ? 1 : 0);
    if (hidden) {
        DebugLogPrint(4, "hide mkdir path=%s", DebugPreview(pathView).c_str());
        errno = EACCES;
        return -1;
    }
    if (HiddenPathPolicy::IsReadOnly(uid, std::string(pathView))) {
        DebugLogPrint(4, "read-only block mkdir path=%s", std::string(pathView).c_str());
        errno = EROFS;
        return -1;
    }

    std::string actualPath = path != nullptr ? ProcessRedirectPath(path, uid) : "";
    const char* targetPath = path != nullptr ? actualPath.c_str() : nullptr;
    auto fn = reinterpret_cast<int (*)(const char*, mode_t)>(gOriginalMkdir);
    if (fn) {
        return fn(targetPath, mode);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedMknod(const char* path, mode_t mode, dev_t dev) {
    const uint32_t uid = gActiveUid;
    if (uid == 0) {
        auto fn = reinterpret_cast<int (*)(const char*, mode_t, dev_t)>(gOriginalMknod);
        return fn ? fn(path, mode, dev) : -1;
    }

    RecordMonitorEventPath(uid, "CREATE", path);
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    const bool hidden = ShouldHideLowerFsCreatePath(pathView);
    DebugLogPrint(4, "create-trace lower_mknod uid=%u path=%s mode=%o dev=%llu hidden=%d",
                  static_cast<unsigned>(uid), DebugPreview(pathView).c_str(), mode,
                  static_cast<unsigned long long>(dev), hidden ? 1 : 0);
    if (hidden) {
        DebugLogPrint(4, "hide mknod path=%s", DebugPreview(pathView).c_str());
        errno = EPERM;
        return -1;
    }
    if (HiddenPathPolicy::IsReadOnly(uid, std::string(pathView))) {
        DebugLogPrint(4, "read-only block mknod path=%s", std::string(pathView).c_str());
        errno = EROFS;
        return -1;
    }

    std::string actualPath = path != nullptr ? ProcessRedirectPath(path, uid) : "";
    const char* targetPath = path != nullptr ? actualPath.c_str() : nullptr;
    auto fn = reinterpret_cast<int (*)(const char*, mode_t, dev_t)>(gOriginalMknod);
    if (fn) {
        return fn(targetPath, mode, dev);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedOpen(const char* path, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list args;
        va_start(args, flags);
        mode = static_cast<mode_t>(va_arg(args, int));
        va_end(args);
    }

    const uint32_t uid = gActiveUid;
    if (uid == 0) {
        auto fn = reinterpret_cast<int (*)(const char*, int, ...)>(gOriginalOpen);
        if (fn) {
            if ((flags & O_CREAT) != 0) return fn(path, flags, mode);
            return fn(path, flags);
        }
        errno = ENOSYS;
        return -1;
    }

    if ((flags & O_CREAT) == 0) {
        RecordMonitorEventPath(uid, "OPEN", path);
    } else {
        RecordMonitorEventPath(uid, "CREATE", path);
    }

    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    const bool hidden = (flags & O_CREAT) != 0 && ShouldHideLowerFsCreatePath(pathView);
    if ((flags & O_CREAT) != 0) {
        DebugLogPrint(4, "create-trace lower_open uid=%u path=%s flags=0x%x mode=%o hidden=%d",
                      static_cast<unsigned>(uid), DebugPreview(pathView).c_str(), flags, mode,
                      hidden ? 1 : 0);
    }
    if (hidden) {
        DebugLogPrint(4, "hide open create path=%s flags=0x%x", DebugPreview(pathView).c_str(),
                      flags);
        errno = EPERM;
        return -1;
    }
    if (HiddenPathPolicy::IsReadOnly(uid, std::string(pathView))) {
        int accmode = flags & O_ACCMODE;
        if (accmode == O_WRONLY || accmode == O_RDWR || (flags & (O_CREAT | O_TRUNC | O_APPEND))) {
            DebugLogPrint(4, "read-only block open path=%s", std::string(pathView).c_str());
            errno = EROFS;
            return -1;
        }
    }

    std::string actualPath = path != nullptr ? ProcessRedirectPath(path, uid) : "";
    const char* targetPath = path != nullptr ? actualPath.c_str() : nullptr;
    auto fn = reinterpret_cast<int (*)(const char*, int, ...)>(gOriginalOpen);
    if (fn) {
        if ((flags & O_CREAT) != 0) {
            return fn(targetPath, flags, mode);
        }
        return fn(targetPath, flags);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedOpen2(const char* path, int flags) {
    const uint32_t uid = gActiveUid;
    if (uid == 0) {
        auto fn = reinterpret_cast<int (*)(const char*, int)>(gOriginalOpen2);
        return fn ? fn(path, flags) : -1;
    }

    if ((flags & O_CREAT) == 0) {
        RecordMonitorEventPath(uid, "OPEN", path);
    } else {
        RecordMonitorEventPath(uid, "CREATE", path);
    }
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    const bool hidden = (flags & O_CREAT) != 0 && ShouldHideLowerFsCreatePath(pathView);
    if ((flags & O_CREAT) != 0) {
        DebugLogPrint(4, "create-trace lower_open2 uid=%u path=%s flags=0x%x hidden=%d",
                      static_cast<unsigned>(uid), DebugPreview(pathView).c_str(), flags,
                      hidden ? 1 : 0);
    }
    if (hidden) {
        DebugLogPrint(4, "hide __open_2 create path=%s flags=0x%x", DebugPreview(pathView).c_str(),
                      flags);
        errno = EPERM;
        return -1;
    }
    if (HiddenPathPolicy::IsReadOnly(uid, std::string(pathView))) {
        int accmode = flags & O_ACCMODE;
        if (accmode == O_WRONLY || accmode == O_RDWR || (flags & (O_CREAT | O_TRUNC | O_APPEND))) {
            DebugLogPrint(4, "read-only block open2 path=%s", std::string(pathView).c_str());
            errno = EROFS;
            return -1;
        }
    }

    std::string actualPath = path != nullptr ? ProcessRedirectPath(path, uid) : "";
    const char* targetPath = path != nullptr ? actualPath.c_str() : nullptr;
    auto fn = reinterpret_cast<int (*)(const char*, int)>(gOriginalOpen2);
    if (fn) {
        return fn(targetPath, flags);
    }
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedUnlinkLibc(const char* path) {
    const uint32_t uid = gActiveUid;
    if (uid == 0) {
        auto fn = reinterpret_cast<int (*)(const char*)>(gOriginalUnlinkLibc);
        return fn ? fn(path) : -1;
    }

    RecordMonitorEventPath(uid, "DELETE", path);
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (HiddenPathPolicy::IsReadOnly(uid, std::string(pathView))) {
        DebugLogPrint(4, "read-only block unlink libc path=%s", std::string(pathView).c_str());
        errno = EROFS;
        return -1;
    }
    std::string actualPath = path != nullptr ? ProcessRedirectPath(path, uid) : "";
    const char* targetPath = path != nullptr ? actualPath.c_str() : nullptr;
    auto fn = reinterpret_cast<int (*)(const char*)>(gOriginalUnlinkLibc);
    if (fn) return fn(targetPath);
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedRmdirLibc(const char* path) {
    const uint32_t uid = gActiveUid;
    if (uid == 0) {
        auto fn = reinterpret_cast<int (*)(const char*)>(gOriginalRmdirLibc);
        return fn ? fn(path) : -1;
    }

    RecordMonitorEventPath(uid, "DELETE", path);
    const std::string_view pathView = path != nullptr ? std::string_view(path) : std::string_view();
    if (HiddenPathPolicy::IsReadOnly(uid, std::string(pathView))) {
        DebugLogPrint(4, "read-only block rmdir libc path=%s", std::string(pathView).c_str());
        errno = EROFS;
        return -1;
    }
    std::string actualPath = path != nullptr ? ProcessRedirectPath(path, uid) : "";
    const char* targetPath = path != nullptr ? actualPath.c_str() : nullptr;
    auto fn = reinterpret_cast<int (*)(const char*)>(gOriginalRmdirLibc);
    if (fn) return fn(targetPath);
    errno = ENOSYS;
    return -1;
}

extern "C" int WrappedRenameLibc(const char* oldpath, const char* newpath) {
    const uint32_t uid = gActiveUid;
    if (uid == 0) {
        auto fn = reinterpret_cast<int (*)(const char*, const char*)>(gOriginalRenameLibc);
        return fn ? fn(oldpath, newpath) : -1;
    }

    RecordMonitorEventPath(uid, "RENAME", oldpath);
    const std::string_view oldView = oldpath != nullptr ? std::string_view(oldpath) : std::string_view();
    const std::string_view newView = newpath != nullptr ? std::string_view(newpath) : std::string_view();

    if (HiddenPathPolicy::IsReadOnly(uid, std::string(oldView)) || HiddenPathPolicy::IsReadOnly(uid, std::string(newView))) {
        DebugLogPrint(4, "read-only block rename libc old=%s new=%s", std::string(oldView).c_str(), std::string(newView).c_str());
        errno = EROFS;
        return -1;
    }

    std::string sOld = oldpath != nullptr ? ProcessRedirectPath(oldpath, uid) : "";
    const char* tOld = oldpath != nullptr ? sOld.c_str() : nullptr;
    std::string sNew = newpath != nullptr ? ProcessRedirectPath(newpath, uid) : "";
    const char* tNew = newpath != nullptr ? sNew.c_str() : nullptr;
    auto fn = reinterpret_cast<int (*)(const char*, const char*)>(gOriginalRenameLibc);
    if (fn) return fn(tOld, tNew);
    errno = ENOSYS;
    return -1;
}

// Path hook wrappers

bool HiddenPathPolicy::IsTestHiddenUid(uint32_t uid) {
    {
        std::lock_guard<std::mutex> lock(gUidHideCacheMutex);
        const auto it = gUidHideCache.find(uid);
        if (it != gUidHideCache.end()) {
            return it->second;
        }
    }

    const std::optional<bool> resolved = ResolveShouldHideUidWithPackageManager(uid);
    if (!resolved.has_value()) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(gUidHideCacheMutex);
        gUidHideCache[uid] = *resolved;
    }
    return *resolved;
}

bool HiddenPathPolicy::ShouldHideTestPath(uint32_t uid, std::string_view path) {
    if (!IsTestHiddenUid(uid)) {
        return false;
    }
    if (IsHiddenRootDirectoryPath(path)) {
        return false;
    }
    return IsAnyHiddenSubtreePath(path);
}

// Mirror the original app-accessible gate: sanitize only when needed, then delegate.
bool WrappedIsAppAccessiblePath(void* fuse, const std::string& path, uint32_t uid) {
    if (gOriginalIsAppAccessiblePath == nullptr) {
        return false;
    }
    ScopedActiveUid scopedUid(uid); // 设置当前 FUSE 上下文的 UID
    if (!UnicodePolicy::NeedsSanitization(path)) {
        UnicodePolicy::LogSuspiciousDirectPath("app_accessible", path);
        if (ShouldLogLimited(gAppAccessibleLogCount)) {
            DebugLogPrint(3, "app_accessible direct uid=%u path=%s", uid,
                          DebugPreview(path).c_str());
        }
        NoteHiddenSubtreePathForCache(path);
        if (HiddenPathPolicy::ShouldHideTestPath(uid, path)) {
            DebugLogPrint(4, "hide test path uid=%u path=%s", static_cast<unsigned>(uid),
                          DebugPreview(path).c_str());
            return false;
        }
        return gOriginalIsAppAccessiblePath(fuse, path, uid);
    }
    std::string sanitized(path);
    UnicodePolicy::RewriteString(sanitized);
    if (ShouldLogLimited(gAppAccessibleLogCount)) {
        DebugLogPrint(3, "app_accessible rewrite uid=%u old=%s new=%s", uid,
                      DebugPreview(path).c_str(), DebugPreview(sanitized).c_str());
    }
    NoteHiddenSubtreePathForCache(sanitized);
    if (HiddenPathPolicy::ShouldHideTestPath(uid, sanitized)) {
        DebugLogPrint(4, "hide test path uid=%u path=%s src=%s", static_cast<unsigned>(uid),
                      DebugPreview(sanitized).c_str(), DebugPreview(path).c_str());
        return false;
    }
    return gOriginalIsAppAccessiblePath(fuse, sanitized, uid);
}

// The package-owned helper only sanitizes the first path argument on the device build.
bool WrappedIsPackageOwnedPath(const std::string& lhs, const std::string& rhs) {
    if (gOriginalIsPackageOwnedPath == nullptr) {
        return false;
    }
    if (!UnicodePolicy::NeedsSanitization(lhs)) {
        UnicodePolicy::LogSuspiciousDirectPath("package_owned", lhs);
        if (ShouldLogLimited(gPackageOwnedLogCount)) {
            DebugLogPrint(3, "package_owned direct lhs=%s rhs=%s", DebugPreview(lhs).c_str(),
                          DebugPreview(rhs).c_str());
        }
        return gOriginalIsPackageOwnedPath(lhs, rhs);
    }
    std::string sanitizedLhs(lhs);
    UnicodePolicy::RewriteString(sanitizedLhs);
    if (ShouldLogLimited(gPackageOwnedLogCount)) {
        DebugLogPrint(3, "package_owned rewrite lhs=%s new=%s rhs=%s", DebugPreview(lhs).c_str(),
                      DebugPreview(sanitizedLhs).c_str(), DebugPreview(rhs).c_str());
    }
    return gOriginalIsPackageOwnedPath(sanitizedLhs, rhs);
}

// WrappedIsBpfBackingPath
bool WrappedIsBpfBackingPath(const std::string& path) {
    if (gOriginalIsBpfBackingPath == nullptr) {
        return false;
    }
    if (!UnicodePolicy::NeedsSanitization(path)) {
        UnicodePolicy::LogSuspiciousDirectPath("bpf_backing", path);
        if (ShouldLogLimited(gBpfBackingLogCount)) {
            DebugLogPrint(3, "bpf_backing direct path=%s", DebugPreview(path).c_str());
        }
        return gOriginalIsBpfBackingPath(path);
    }
    std::string sanitized(path);
    UnicodePolicy::RewriteString(sanitized);
    if (ShouldLogLimited(gBpfBackingLogCount)) {
        DebugLogPrint(3, "bpf_backing rewrite old=%s new=%s", DebugPreview(path).c_str(),
                      DebugPreview(sanitized).c_str());
    }
    return gOriginalIsBpfBackingPath(sanitized);
}

// Keep libc strcasecmp behavior aligned with the original case-folding compare.
extern "C" int WrappedStrcasecmp(const char* lhs, const char* rhs) {
    const size_t lhsLen = (lhs != nullptr) ? std::strlen(lhs) : 0;
    const size_t rhsLen = (rhs != nullptr) ? std::strlen(rhs) : 0;
    const int result = UnicodePolicy::CompareCaseFoldIgnoringDefaultIgnorables(
        reinterpret_cast<const uint8_t*>(lhs ? lhs : ""), lhsLen,
        reinterpret_cast<const uint8_t*>(rhs ? rhs : ""), rhsLen);
    if (ShouldLogLimited(gStrcasecmpLogCount)) {
        DebugLogPrint(3, "strcasecmp lhs=%s rhs=%s result=%d",
                      DebugPreview(std::string_view(lhs ? lhs : "", lhsLen)).c_str(),
                      DebugPreview(std::string_view(rhs ? rhs : "", rhsLen)).c_str(), result);
    }
    return result;
}

// ABI adapter for android::base::EqualsIgnoreCase(string_view, string_view).
extern "C" bool WrappedEqualsIgnoreCaseAbi(const char* lhsData, size_t lhsSize, const char* rhsData,
                                           size_t rhsSize) {
    const int result = UnicodePolicy::CompareCaseFoldIgnoringDefaultIgnorables(
        reinterpret_cast<const uint8_t*>(lhsData ? lhsData : ""), lhsSize,
        reinterpret_cast<const uint8_t*>(rhsData ? rhsData : ""), rhsSize);
    if (ShouldLogLimited(gEqualsIgnoreCaseLogCount)) {
        DebugLogPrint(3, "equals_ignore_case lhs=%s rhs=%s result=%d",
                      DebugPreview(std::string_view(lhsData ? lhsData : "", lhsSize)).c_str(),
                      DebugPreview(std::string_view(rhsData ? rhsData : "", rhsSize)).c_str(),
                      result);
    }
    return result == 0;
}

bool IsTestHiddenUid(uint32_t uid) {
    return HiddenPathPolicy::IsTestHiddenUid(uid);
}

bool ShouldHideTestPath(uint32_t uid, std::string_view path) {
    return HiddenPathPolicy::ShouldHideTestPath(uid, path);
}

}  // namespace fusehide
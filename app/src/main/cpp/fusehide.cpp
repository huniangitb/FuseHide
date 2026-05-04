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

#include "fusehide/state.hpp"
std::atomic<bool> gMonitorEnabled{false};
namespace fusehide {
UHasBinaryPropertyFn gUHasBinaryProperty = u_hasBinaryProperty;
HookInstaller gHookInstaller = nullptr;
JavaVM* gJavaVm = nullptr;
std::once_flag gXzCrcInitOnce;
IsAppAccessiblePathFn gOriginalIsAppAccessiblePath = nullptr;
IsPackageOwnedPathFn gOriginalIsPackageOwnedPath = nullptr;
IsBpfBackingPathFn gOriginalIsBpfBackingPath = nullptr;
void* gOriginalStrcasecmp = nullptr;
void* gOriginalEqualsIgnoreCase = nullptr;

std::atomic<int> gAppAccessibleLogCount{0};
std::atomic<int> gPackageOwnedLogCount{0};
std::atomic<int> gBpfBackingLogCount{0};
std::atomic<int> gStrcasecmpLogCount{0};
std::atomic<int> gEqualsIgnoreCaseLogCount{0};
std::atomic<int> gReplyErrFallbackLogCount{0};
std::atomic<int> gErrnoRemapLogCount{0};
std::atomic<int> gSuspiciousDirectLogCount{0};
std::mutex gUidHideCacheMutex;
std::unordered_map<uint32_t, bool> gUidHideCache;
std::shared_ptr<const HideConfig> gHideConfig = std::make_shared<HideConfig>(DefaultHideConfig());

std::mutex gUidPackagesCacheMutex;
std::unordered_map<uint32_t, std::vector<std::string>> gUidPackagesCache;

namespace {}  // namespace

HideConfig DefaultHideConfig() {
    HideConfig config;
    config.enableHideAllRootEntries = kEnableHideAllRootEntries;
    for (const auto& value : kHideAllRootEntriesExemptions) {
        config.hideAllRootEntriesExemptions.emplace_back(value);
    }
    for (const auto& value : kHiddenRootEntryNames) {
        config.hiddenRootEntryNames.emplace_back(value);
    }
    for (const auto& value : kHiddenRelativePaths) {
        config.hiddenRelativePaths.emplace_back(value);
    }
    for (const auto& value : kHiddenPackages) {
        config.hiddenPackages.emplace_back(value);
    }
    return config;
}

std::shared_ptr<const HideConfig> CurrentHideConfig() {
    return std::atomic_load_explicit(&gHideConfig, std::memory_order_acquire);
}

void ApplyHideConfig(HideConfig config) {
    auto next = std::make_shared<const HideConfig>(std::move(config));
    std::atomic_store_explicit(&gHideConfig, std::move(next), std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(gUidHideCacheMutex);
        gUidHideCache.clear();
    }
    {
        std::lock_guard<std::mutex> lock(gUidPackagesCacheMutex);
        gUidPackagesCache.clear();
    }
    DebugLogPrint(4, "applied hide config hide_all=%d exemptions=%zu roots=%zu packages=%zu redirects=%zu readonlies=%zu",
                  CurrentHideConfig()->enableHideAllRootEntries ? 1 : 0,
                  CurrentHideConfig()->hideAllRootEntriesExemptions.size(),
                  CurrentHideConfig()->hiddenRootEntryNames.size(),
                  CurrentHideConfig()->hiddenPackages.size(),
                  CurrentHideConfig()->redirectRules.size(),
                  CurrentHideConfig()->readOnlyRules.size());
}

bool IsHiddenPackageName(std::string_view packageName) {
    const auto config = CurrentHideConfig();
    for (const auto& hiddenPackage : config->hiddenPackages) {
        if (packageName == hiddenPackage) {
            return true;
        }
    }
    return false;
}

namespace {

JNIEnv* GetJniEnv(bool* didAttach) {
    if (didAttach != nullptr) {
        *didAttach = false;
    }
    if (gJavaVm == nullptr) {
        return nullptr;
    }
    JNIEnv* env = nullptr;
    const jint status = gJavaVm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (status == JNI_OK) {
        return env;
    }
    if (status != JNI_EDETACHED) {
        return nullptr;
    }
    if (gJavaVm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
        return nullptr;
    }
    if (didAttach != nullptr) {
        *didAttach = true;
    }
    return env;
}

}  // namespace

void ReportFileEvent(const char* eventType, const char* path, uint32_t uid) {
    bool didAttach = false;
    JNIEnv* env = GetJniEnv(&didAttach);
    if (env == nullptr) return;
    
    jclass entryClass = env->FindClass("io/github/xiaotong6666/fusehide/Entry");
    if (entryClass != nullptr) {
        jmethodID reportMethod = env->GetStaticMethodID(entryClass, "reportFileEvent", "(Ljava/lang/String;Ljava/lang/String;I)V");
        if (reportMethod != nullptr && !env->ExceptionCheck()) {
            jstring jEventType = env->NewStringUTF(eventType);
            jstring jPath = env->NewStringUTF(path);
            env->CallStaticVoidMethod(entryClass, reportMethod, jEventType, jPath, (jint)uid);
            env->DeleteLocalRef(jEventType);
            env->DeleteLocalRef(jPath);
        }
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        env->DeleteLocalRef(entryClass);
    }
    
    if (didAttach && gJavaVm != nullptr) {
        gJavaVm->DetachCurrentThread();
    }
}

std::vector<std::string> GetPackagesForUid(uint32_t uid) {
    {
        std::lock_guard<std::mutex> lock(gUidPackagesCacheMutex);
        auto it = gUidPackagesCache.find(uid);
        if (it != gUidPackagesCache.end()) {
            return it->second;
        }
    }

    bool didAttach = false;
    JNIEnv* env = GetJniEnv(&didAttach);
    if (env == nullptr) {
        return {};
    }

    auto finish = [&](std::vector<std::string> value) {
        {
            std::lock_guard<std::mutex> lock(gUidPackagesCacheMutex);
            gUidPackagesCache[uid] = value;
        }
        if (didAttach) {
            gJavaVm->DetachCurrentThread();
        }
        return value;
    };

    jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
    if (activityThreadClass == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return finish({});
    }
    jmethodID currentApplication = env->GetStaticMethodID(activityThreadClass, "currentApplication", "()Landroid/app/Application;");
    if (currentApplication == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(activityThreadClass);
        return finish({});
    }
    jobject application = env->CallStaticObjectMethod(activityThreadClass, currentApplication);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(activityThreadClass);
        return finish({});
    }
    env->DeleteLocalRef(activityThreadClass);
    if (application == nullptr) return finish({});

    jclass applicationClass = env->GetObjectClass(application);
    jmethodID getPackageManager = env->GetMethodID(applicationClass, "getPackageManager", "()Landroid/content/pm/PackageManager;");
    if (getPackageManager == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(applicationClass);
        env->DeleteLocalRef(application);
        return finish({});
    }
    jobject packageManager = env->CallObjectMethod(application, getPackageManager);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(applicationClass);
        env->DeleteLocalRef(application);
        return finish({});
    }
    env->DeleteLocalRef(applicationClass);
    env->DeleteLocalRef(application);
    if (packageManager == nullptr) return finish({});

    jclass packageManagerClass = env->FindClass("android/content/pm/PackageManager");
    jmethodID getPackagesForUid = env->GetMethodID(packageManagerClass, "getPackagesForUid", "(I)[Ljava/lang/String;");
    if (getPackagesForUid == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(packageManagerClass);
        env->DeleteLocalRef(packageManager);
        return finish({});
    }

    jobjectArray packages = static_cast<jobjectArray>(env->CallObjectMethod(packageManager, getPackagesForUid, (jint)uid));
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(packageManagerClass);
        env->DeleteLocalRef(packageManager);
        return finish({});
    }
    env->DeleteLocalRef(packageManagerClass);
    env->DeleteLocalRef(packageManager);

    std::vector<std::string> pkgList;
    if (packages != nullptr) {
        const jsize count = env->GetArrayLength(packages);
        for (jsize i = 0; i < count; ++i) {
            jstring packageName = static_cast<jstring>(env->GetObjectArrayElement(packages, i));
            if (packageName == nullptr) continue;
            const char* packageNameChars = env->GetStringUTFChars(packageName, nullptr);
            if (packageNameChars != nullptr) {
                pkgList.emplace_back(packageNameChars);
                env->ReleaseStringUTFChars(packageName, packageNameChars);
            }
            env->DeleteLocalRef(packageName);
        }
        env->DeleteLocalRef(packages);
    }
    return finish(pkgList);
}

bool IsUidInPackage(uint32_t uid, const std::string& targetPkg) {
    auto pkgs = GetPackagesForUid(uid);
    for (const auto& pkg : pkgs) {
        if (pkg == targetPkg) return true;
    }
    return false;
}

std::optional<bool> ResolveShouldHideUidWithPackageManager(uint32_t uid) {
    auto pkgs = GetPackagesForUid(uid);
    bool shouldHide = false;
    for (const auto& pkg : pkgs) {
        if (IsHiddenPackageName(pkg)) {
            shouldHide = true;
            break;
        }
    }
    DebugLogPrint(4, "resolved uid=%u hide=%d", static_cast<unsigned>(uid), shouldHide ? 1 : 0);
    return shouldHide;
}

}  // namespace fusehide
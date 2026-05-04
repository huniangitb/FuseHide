/*
 * Copyright (C) 2026 XiaoTong6666
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.xiaotong6666.fusehide;

import android.app.AndroidAppHelper;
import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import androidx.core.content.ContextCompat;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;
import java.io.File;
import java.io.FileWriter;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.util.LinkedList;
import java.util.List;

public class Entry implements IXposedHookLoadPackage {
    private static final String APP_PACKAGE = "io.github.xiaotong6666.fusehide";
    private static final String ACTION_GET_STATUS = APP_PACKAGE + ".GET_STATUS";
    private static final String PACKAGE_MEDIA = "com.android.providers.media.module";
    private static final String PACKAGE_MEDIA_GOOGLE = "com.google.android.providers.media.module";
    private static final long CONFIG_RETRY_DELAY_MS = 15000L;
    private static final int CONFIG_MAX_RETRIES = 8;

    private Handler mainHandler;
    private Application hookedApplication;
    private boolean configLoadCompleted;
    private boolean configLoadInFlight;
    private int pendingConfigRetryCount;
    
    // 监控日志后台写入线程
    private Thread monitorThread = null;
    private File monitorLogFile = null;

    private final Runnable configRetryRunnable = new Runnable() {
        @Override
        public void run() {
            startConfigReload("delayed_retry_" + pendingConfigRetryCount);
        }
    };

    private Handler getMainHandler() {
        if (mainHandler == null) {
            mainHandler = new Handler(Looper.getMainLooper());
        }
        return mainHandler;
    }

    private static HideConfig currentNativeHideConfig() {
        return new HideConfig(
                HideConfigNativeBridge.getCurrentEnableHideAllRootEntries(),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHideAllRootEntriesExemptions()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenRootEntryNames()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenRelativePaths()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentHiddenPackages()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentRedirectRules()),
                java.util.Arrays.asList(HideConfigNativeBridge.getCurrentReadOnlyRules())
        );
    }

    private static void sendConfigStatus(
            Application application, String requestedToken, boolean applied, String message) {
        application.sendBroadcast(new Intent(HideConfigStore.ACTION_SET_CONFIG_STATUS)
                .setPackage(APP_PACKAGE)
                .putExtra(HideConfigStore.EXTRA_RELOAD_TOKEN, requestedToken)
                .putExtra(HideConfigStore.EXTRA_RELOAD_APPLIED, applied)
                .putExtra(HideConfigStore.EXTRA_RELOAD_MESSAGE, message));
    }

    private static void finishConfigReload(
            Application application,
            String requestedToken,
            android.os.Bundle bundle,
            String source,
            BroadcastReceiver.PendingResult pendingResult) {
        try {
            final HideConfig config = HideConfigStore.fromBundle(bundle);
            final String bundleToken = HideConfigStore.reloadTokenFromBundle(bundle);
            final boolean tokenMatches = requestedToken != null && requestedToken.equals(bundleToken);
            boolean applied = false;
            String message;
            if (bundle == null || config == null) {
                message = "hide config unavailable";
            } else if (!tokenMatches) {
                message = "reload token mismatch";
            } else {
                applied = HideConfigStore.applyBundleToNative(bundle);
                if (applied) {
                    HideConfigStore.saveInjectedProcessSnapshot(application, config, bundleToken);
                    message = "hide config applied";
                } else {
                    message = "apply failed";
                }
            }
            sendConfigStatus(application, requestedToken, applied, message);
            Log.d("FuseHide", "config reload source=" + source + " applied=" + applied);
        } finally {
            pendingResult.finish();
        }
    }

    private void onConfigReloadFinished(String source, boolean applied) {
        configLoadInFlight = false;
        if (applied) {
            configLoadCompleted = true;
            pendingConfigRetryCount = 0;
            getMainHandler().removeCallbacks(configRetryRunnable);
            return;
        }
        scheduleConfigRetry(source);
    }

    private void scheduleConfigRetry(String source) {
        if (hookedApplication == null || configLoadCompleted) return;
        if (pendingConfigRetryCount >= CONFIG_MAX_RETRIES) return;
        pendingConfigRetryCount += 1;
        getMainHandler().removeCallbacks(configRetryRunnable);
        getMainHandler().postDelayed(configRetryRunnable, CONFIG_RETRY_DELAY_MS);
    }

    private void startConfigReload(String source) {
        if (hookedApplication == null || configLoadCompleted || configLoadInFlight) return;
        configLoadInFlight = true;
        HideConfigStore.reloadInjectedProcessConfig(hookedApplication, applied -> onConfigReloadFinished(source, applied));
    }

    // ========== 监控日志落地逻辑 (存储在 MediaProvider 端) ==========
    private void manageMonitorThread() {
        boolean isEnabled = HideConfigNativeBridge.isMonitorEnabled();
        if (isEnabled && (monitorThread == null || !monitorThread.isAlive())) {
            monitorThread = new Thread(() -> {
                while (HideConfigNativeBridge.isMonitorEnabled()) {
                    flushMonitorLogs();
                    try { Thread.sleep(1000); } catch (InterruptedException e) { break; }
                }
            });
            monitorThread.start();
        }
    }

    private synchronized void flushMonitorLogs() {
        String[] events = HideConfigNativeBridge.fetchMonitorEvents();
        if (events == null || events.length == 0 || monitorLogFile == null) return;
        try (FileWriter fw = new FileWriter(monitorLogFile, true);
             BufferedWriter bw = new BufferedWriter(fw)) {
            String time = new java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(new java.util.Date());
            for (String ev : events) {
                bw.write("[" + time + "] " + ev);
                bw.newLine();
            }
            // 限制文件大小防止无限膨胀 (限制在大约 2MB)
            if (monitorLogFile.length() > 2 * 1024 * 1024L) {
                trimMonitorLogFile();
            }
        } catch (Exception e) {
            Log.e("FuseHide", "Failed to write monitor logs", e);
        }
    }

    private synchronized void trimMonitorLogFile() {
        if (monitorLogFile == null || !monitorLogFile.exists()) return;
        try {
            LinkedList<String> lines = new LinkedList<>();
            try (BufferedReader br = new BufferedReader(new FileReader(monitorLogFile))) {
                String line;
                while ((line = br.readLine()) != null) {
                    lines.add(line);
                    if (lines.size() > 2000) lines.removeFirst(); // 只保留最后2000行
                }
            }
            try (BufferedWriter bw = new BufferedWriter(new FileWriter(monitorLogFile, false))) {
                for (String l : lines) {
                    bw.write(l);
                    bw.newLine();
                }
            }
        } catch (Exception e) {
            Log.e("FuseHide", "Failed to trim logs", e);
        }
    }

    private synchronized String[] readLatestLogs() {
        if (monitorLogFile == null || !monitorLogFile.exists()) return new String[0];
        LinkedList<String> lines = new LinkedList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(monitorLogFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                lines.add(line);
                if (lines.size() > 800) lines.removeFirst(); // 限制广播大小，最多返回最后800条
            }
        } catch (Exception e) {
            Log.e("FuseHide", "Read logs failed", e);
        }
        return lines.toArray(new String[0]);
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) {
        try {
            if (PACKAGE_MEDIA.equals(loadPackageParam.packageName)
                    || PACKAGE_MEDIA_GOOGLE.equals(loadPackageParam.packageName)) {
                System.loadLibrary("fusehide");
                Log.d("FuseHide", "injected");
                if ((loadPackageParam.appInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                    try {
                        XposedHelpers.findAndHookMethod("com.android.providers.media.MediaProvider",
                                loadPackageParam.classLoader, "isUidAllowedAccessToDataOrObbPathForFuse",
                                int.class, String.class, new XC_MethodHook() {
                                    @Override
                                    protected void afterHookedMethod(MethodHookParam param) { }
                                });
                    } catch (Throwable th) { }
                }
                new Handler(Looper.getMainLooper()).post(new MainThreadTask(0, this));
            }
        } catch (Throwable th) {
            Log.e("FuseHide", "handleLoadPackage", th);
        }
    }

    public void registerStatusReceiver() {
        try {
            Application application = AndroidAppHelper.currentApplication();
            if (application == null) return;
            hookedApplication = application;
            // 初始化日志文件在 MediaProvider 进程自身的缓存目录
            monitorLogFile = new File(application.getCacheDir(), "fusehide_monitor_events.log");

            StatusBroadcastReceiver receiver = new StatusBroadcastReceiver(application, 0);
            IntentFilter filter = new IntentFilter(ACTION_GET_STATUS);
            if (Build.VERSION.SDK_INT >= 33) application.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED);
            else ContextCompat.registerReceiver(application, receiver, filter, ContextCompat.RECEIVER_EXPORTED);

            BroadcastReceiver configReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    final PendingResult pendingResult = goAsync();
                    final String requestedToken = intent.getStringExtra(HideConfigStore.EXTRA_RELOAD_TOKEN);
                    final android.os.Bundle bundle = HideConfigStore.loadViaProviderBundle(application);
                    final String providerToken = HideConfigStore.reloadTokenFromBundle(bundle);
                    if (bundle != null && (requestedToken != null && requestedToken.equals(providerToken))) {
                        finishConfigReload(application, requestedToken, bundle, "provider", pendingResult);
                        return;
                    }
                    HideConfigStore.requestInjectedProcessConfigBundle(application,
                            fallbackBundle -> finishConfigReload(application, requestedToken, fallbackBundle, "broadcast_fallback", pendingResult));
                }
            };
            IntentFilter configFilter = new IntentFilter(HideConfigStore.ACTION_RELOAD_HIDE_CONFIG);
            if (Build.VERSION.SDK_INT >= 33) application.registerReceiver(configReceiver, configFilter, Context.RECEIVER_EXPORTED);
            else ContextCompat.registerReceiver(application, configReceiver, configFilter, ContextCompat.RECEIVER_EXPORTED);

            BroadcastReceiver queryReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    Intent reply = new Intent(HideConfigStore.ACTION_SET_APPLIED_HIDE_CONFIG)
                            .setPackage(APP_PACKAGE)
                            .putExtra(HideConfigStore.EXTRA_QUERY_TOKEN, intent.getStringExtra(HideConfigStore.EXTRA_QUERY_TOKEN))
                            .putExtras(HideConfigStore.toBundle(currentNativeHideConfig()));
                    application.sendBroadcast(reply);
                }
            };
            IntentFilter queryFilter = new IntentFilter(HideConfigStore.ACTION_GET_APPLIED_HIDE_CONFIG);
            if (Build.VERSION.SDK_INT >= 33) application.registerReceiver(queryReceiver, queryFilter, Context.RECEIVER_EXPORTED);
            else ContextCompat.registerReceiver(application, queryReceiver, queryFilter, ContextCompat.RECEIVER_EXPORTED);

            // ========== 处理监控命令和状态获取 ==========
            BroadcastReceiver monitorReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    String action = intent.getAction();
                    if ("io.github.xiaotong6666.fusehide.GET_MONITOR_STATUS".equals(action)) {
                        // 报告真实 JNI 状态
                        boolean isEnabled = HideConfigNativeBridge.isMonitorEnabled();
                        Intent reply = new Intent("io.github.xiaotong6666.fusehide.SYNC_MONITOR_STATUS")
                                .setPackage(APP_PACKAGE)
                                .putExtra("enabled", isEnabled);
                        application.sendBroadcast(reply);
                    } 
                    else if ("io.github.xiaotong6666.fusehide.SET_MONITOR_ENABLED".equals(action)) {
                        boolean enable = intent.getBooleanExtra("enabled", false);
                        HideConfigNativeBridge.setMonitorEnabled(enable);
                        manageMonitorThread();
                        // 回传最新状态
                        Intent reply = new Intent("io.github.xiaotong6666.fusehide.SYNC_MONITOR_STATUS")
                                .setPackage(APP_PACKAGE)
                                .putExtra("enabled", enable);
                        application.sendBroadcast(reply);
                    } 
                    else if ("io.github.xiaotong6666.fusehide.FETCH_EVENTS".equals(action)) {
                        flushMonitorLogs(); // 先强制刷入最新数据
                        String[] events = readLatestLogs();
                        Intent reply = new Intent("io.github.xiaotong6666.fusehide.REPORT_EVENTS")
                                .setPackage(APP_PACKAGE)
                                .putExtra("events", events);
                        application.sendBroadcast(reply);
                    }
                    else if ("io.github.xiaotong6666.fusehide.CLEAR_EVENTS".equals(action)) {
                        HideConfigNativeBridge.fetchMonitorEvents(); // 清空 C++ 队列
                        synchronized (Entry.this) {
                            if (monitorLogFile != null && monitorLogFile.exists()) {
                                monitorLogFile.delete();
                            }
                        }
                        Intent reply = new Intent("io.github.xiaotong6666.fusehide.REPORT_EVENTS")
                                .setPackage(APP_PACKAGE)
                                .putExtra("events", new String[0]); // 返回空列表刷新 UI
                        application.sendBroadcast(reply);
                    }
                }
            };
            IntentFilter monitorFilter = new IntentFilter();
            monitorFilter.addAction("io.github.xiaotong6666.fusehide.GET_MONITOR_STATUS");
            monitorFilter.addAction("io.github.xiaotong6666.fusehide.SET_MONITOR_ENABLED");
            monitorFilter.addAction("io.github.xiaotong6666.fusehide.FETCH_EVENTS");
            monitorFilter.addAction("io.github.xiaotong6666.fusehide.CLEAR_EVENTS");
            if (Build.VERSION.SDK_INT >= 33) application.registerReceiver(monitorReceiver, monitorFilter, Context.RECEIVER_EXPORTED);
            else ContextCompat.registerReceiver(application, monitorReceiver, monitorFilter, ContextCompat.RECEIVER_EXPORTED);

            // 启动时恢复由于之前奔溃或未知原因停止的后台线程（如果 JNI 显示已开启）
            manageMonitorThread();

            startConfigReload("initial");
        } catch (Throwable th) {
            Log.e("FuseHide", "register", th);
        }
    }
}
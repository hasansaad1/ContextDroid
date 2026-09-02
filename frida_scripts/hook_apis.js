"use strict";

function emitJson(obj) {
  try {
    console.log(JSON.stringify(obj));
  } catch (_e) {
    // Intentionally swallow to avoid breaking app flow.
  }
}

function logStatus(status, name, message) {
  emitJson({
    type: "status",
    timestamp: Date.now(),
    status: status,
    name: name,
    message: message || null
  });
}

function logEvent(api, category, args) {
  const payload = {
    type: "event",
    timestamp: Date.now(),
    api: api,
    category: category,
    args: args || {}
  };
  emitJson(payload);
}

function classifyContentUri(uriStr) {
  const s = (uriStr || "").toLowerCase();
  if (s.indexOf("contacts") >= 0) {
    return "contacts";
  }
  if (s.indexOf("call_log") >= 0) {
    return "call_log";
  }
  if (s.indexOf("sms") >= 0 || s.indexOf("mms") >= 0) {
    return "sms";
  }
  if (s.indexOf("calendar") >= 0) {
    return "calendar";
  }
  return "other";
}

Java.perform(function () {
  logEvent("hook_loaded", "lifecycle", { stage: "java_perform", version: "3" });

  function summarizeIntent(intent) {
    if (!intent) {
      return { action: null, target: null };
    }
    let action = null;
    let target = null;
    try {
      action = intent.getAction();
      if (action) {
        action = action.toString();
      }
    } catch (e) {
      action = "<unavailable>";
    }
    try {
      const component = intent.getComponent();
      if (component) {
        target = component.flattenToString();
      } else if (action) {
        target = action;
      }
    } catch (e) {
      target = "<unavailable>";
    }
    return { action: action, target: target };
  }

  function safeHook(name, fn) {
    try {
      fn();
      logStatus("hook_ok", name, null);
    } catch (e) {
      logStatus("hook_fail", name, String(e));
    }
  }

  safeHook("SmsManager.sendTextMessage", function () {
    const SmsManager = Java.use("android.telephony.SmsManager");
    const ol = SmsManager.sendTextMessage.overload(
      "java.lang.String",
      "java.lang.String",
      "java.lang.String",
      "android.app.PendingIntent",
      "android.app.PendingIntent"
    );
    ol.implementation = function (dest, scAddr, text, sentIntent, deliveryIntent) {
      logEvent("SmsManager.sendTextMessage", "sms", {
        destination: dest ? dest.toString() : null,
        text: text ? text.toString() : null
      });
      return ol.call(this, dest, scAddr, text, sentIntent, deliveryIntent);
    };
  });

  safeHook("SmsManager.sendMultipartTextMessage", function () {
    const SmsManager = Java.use("android.telephony.SmsManager");
    const ol = SmsManager.sendMultipartTextMessage.overload(
      "java.lang.String",
      "java.lang.String",
      "java.util.ArrayList",
      "java.util.ArrayList",
      "java.util.ArrayList"
    );
    ol.implementation = function (dest, scAddr, parts, sentIntents, deliveryIntents) {
      logEvent("SmsManager.sendMultipartTextMessage", "sms", {
        destination: dest ? dest.toString() : null,
        partsCount: parts ? parts.size() : 0
      });
      return ol.call(this, dest, scAddr, parts, sentIntents, deliveryIntents);
    };
  });

  safeHook("URL.openConnection", function () {
    const URL = Java.use("java.net.URL");
    const ol = URL.openConnection.overload();
    ol.implementation = function () {
      logEvent("URL.openConnection", "network", { url: this.toString() });
      return ol.call(this);
    };
  });

  safeHook("HttpURLConnection.connect", function () {
    const HttpURLConnection = Java.use("java.net.HttpURLConnection");
    const ol = HttpURLConnection.connect.overload();
    ol.implementation = function () {
      logEvent("HttpURLConnection.connect", "network", { url: this.getURL().toString() });
      return ol.call(this);
    };
  });

  safeHook("OkHttp3", function () {
    const RealCall = Java.use("okhttp3.RealCall");
    const ol = RealCall.execute.overload();
    ol.implementation = function () {
      const req = this.request ? this.request() : null;
      logEvent("okhttp3.RealCall.execute", "network", {
        url: req ? req.url().toString() : null,
        method: req ? req.method().toString() : null
      });
      return ol.call(this);
    };
  });

  safeHook("FileOutputStream.<init>", function () {
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    const ol = FileOutputStream.$init.overload("java.lang.String");
    ol.implementation = function (path) {
      logEvent("FileOutputStream.<init>", "file_io", { path: path ? path.toString() : null });
      return ol.call(this, path);
    };
  });

  safeHook("FileInputStream.<init>", function () {
    const FileInputStream = Java.use("java.io.FileInputStream");
    const ol = FileInputStream.$init.overload("java.lang.String");
    ol.implementation = function (path) {
      logEvent("FileInputStream.<init>", "file_io", { path: path ? path.toString() : null });
      return ol.call(this, path);
    };
  });

  safeHook("File.delete", function () {
    const File = Java.use("java.io.File");
    const ol = File.delete.overload();
    ol.implementation = function () {
      logEvent("File.delete", "file_io", { path: this.getAbsolutePath().toString() });
      return ol.call(this);
    };
  });

  safeHook("Cipher.getInstance", function () {
    const Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function (algorithm) {
      logEvent("Cipher.getInstance", "crypto", { algorithm: algorithm ? algorithm.toString() : null });
      return Cipher.getInstance.overload("java.lang.String").call(this, algorithm);
    };
  });

  safeHook("SecretKeySpec.<init>", function () {
    const SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    const ol = SecretKeySpec.$init.overload("[B", "java.lang.String");
    ol.implementation = function (key, algo) {
      logEvent("SecretKeySpec.<init>", "crypto", { algorithm: algo ? algo.toString() : null });
      return ol.call(this, key, algo);
    };
  });

  safeHook("Method.invoke", function () {
    const Method = Java.use("java.lang.reflect.Method");
    const ol = Method.invoke.overload("java.lang.Object", "[Ljava.lang.Object;");
    ol.implementation = function (obj, argv) {
      const clazz = this.getDeclaringClass().getName().toString();
      const method = this.getName().toString();
      logEvent("Method.invoke", "reflection", { class: clazz, method: method });
      return ol.call(this, obj, argv);
    };
  });

  safeHook("Runtime.exec", function () {
    const Runtime = Java.use("java.lang.Runtime");
    const ol = Runtime.exec.overload("java.lang.String");
    ol.implementation = function (cmd) {
      logEvent("Runtime.exec", "process", { command: cmd ? cmd.toString() : null });
      return ol.call(this, cmd);
    };
  });

  safeHook("ProcessBuilder.start", function () {
    const ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    const ol = ProcessBuilder.start.overload();
    ol.implementation = function () {
      let command = null;
      try {
        command = this.command().toString();
      } catch (e) {
        command = "<unavailable>";
      }
      logEvent("ProcessBuilder.start", "process", { command: command });
      return ol.call(this);
    };
  });

  function logContentUriEvent(api, uri) {
    const uriStr = uri ? uri.toString() : "";
    logEvent(api, "content_access", {
      uri: uriStr,
      uri_type: classifyContentUri(uriStr)
    });
  }

  safeHook("ContentResolver.query", function () {
    const ContentResolver = Java.use("android.content.ContentResolver");
    const ol = ContentResolver.query.overload(
      "android.net.Uri",
      "[Ljava.lang.String;",
      "android.os.Bundle",
      "android.os.CancellationSignal"
    );
    ol.implementation = function (uri, projection, queryArgs, cancellationSignal) {
      logContentUriEvent("ContentResolver.query", uri);
      return ol.call(this, uri, projection, queryArgs, cancellationSignal);
    };
  });

  safeHook("ContentResolver.query_legacy", function () {
    const ContentResolver = Java.use("android.content.ContentResolver");
    const ol = ContentResolver.query.overload(
      "android.net.Uri",
      "[Ljava.lang.String;",
      "java.lang.String",
      "[Ljava.lang.String;",
      "java.lang.String"
    );
    ol.implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
      logContentUriEvent("ContentResolver.query", uri);
      return ol.call(this, uri, projection, selection, selectionArgs, sortOrder);
    };
  });

  safeHook("ContentResolver.insert", function () {
    const ContentResolver = Java.use("android.content.ContentResolver");
    const ol = ContentResolver.insert.overload(
      "android.net.Uri",
      "android.content.ContentValues"
    );
    ol.implementation = function (uri, values) {
      logContentUriEvent("ContentResolver.insert", uri);
      return ol.call(this, uri, values);
    };
  });

  safeHook("ContentResolver.update", function () {
    const ContentResolver = Java.use("android.content.ContentResolver");
    const ol = ContentResolver.update.overload(
      "android.net.Uri",
      "android.content.ContentValues",
      "java.lang.String",
      "[Ljava.lang.String;"
    );
    ol.implementation = function (uri, values, selection, selectionArgs) {
      logContentUriEvent("ContentResolver.update", uri);
      return ol.call(this, uri, values, selection, selectionArgs);
    };
  });

  safeHook("ContentResolver.delete", function () {
    const ContentResolver = Java.use("android.content.ContentResolver");
    const ol = ContentResolver.delete.overload(
      "android.net.Uri",
      "java.lang.String",
      "[Ljava.lang.String;"
    );
    ol.implementation = function (uri, selection, selectionArgs) {
      logContentUriEvent("ContentResolver.delete", uri);
      return ol.call(this, uri, selection, selectionArgs);
    };
  });

  safeHook("ClipboardManager.setPrimaryClip", function () {
    const ClipboardManager = Java.use("android.content.ClipboardManager");
    const ol = ClipboardManager.setPrimaryClip.overload("android.content.ClipData");
    ol.implementation = function (clip) {
      let text = null;
      try {
        if (clip && clip.getItemCount() > 0) {
          text = clip.getItemAt(0).coerceToText(Java.use("android.app.ActivityThread").currentApplication().getApplicationContext()).toString();
        }
      } catch (e) {
        text = "<unavailable>";
      }
      logEvent("ClipboardManager.setPrimaryClip", "clipboard", { content: text });
      return ol.call(this, clip);
    };
  });

  safeHook("Camera.open", function () {
    const Camera = Java.use("android.hardware.Camera");
    const ol = Camera.open.overload();
    ol.implementation = function () {
      logEvent("Camera.open", "camera", {});
      return ol.call(this);
    };
  });

  safeHook("CameraManager.openCamera", function () {
    const CameraManager = Java.use("android.hardware.camera2.CameraManager");
    const ol = CameraManager.openCamera.overload(
      "java.lang.String",
      "android.hardware.camera2.CameraDevice$StateCallback",
      "android.os.Handler"
    );
    ol.implementation = function (cameraId, callback, handler) {
      logEvent("CameraManager.openCamera", "camera", {
        cameraId: cameraId ? cameraId.toString() : null
      });
      return ol.call(this, cameraId, callback, handler);
    };
  });

  safeHook("PackageManager.getInstalledPackages", function () {
    const ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
    const ol = ApplicationPackageManager.getInstalledPackages.overload("int");
    ol.implementation = function (flags) {
      logEvent("PackageManager.getInstalledPackages", "package_manager", { flags: flags });
      return ol.call(this, flags);
    };
  });

  safeHook("PackageManager.getInstalledApplications", function () {
    const ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
    const ol = ApplicationPackageManager.getInstalledApplications.overload("int");
    ol.implementation = function (flags) {
      logEvent("PackageManager.getInstalledApplications", "package_manager", { flags: flags });
      return ol.call(this, flags);
    };
  });

  safeHook("LocationManager.requestLocationUpdates", function () {
    const LocationManager = Java.use("android.location.LocationManager");
    const ol = LocationManager.requestLocationUpdates.overload(
      "java.lang.String",
      "long",
      "float",
      "android.location.LocationListener"
    );
    ol.implementation = function (provider, minTime, minDistance, listener) {
      logEvent("LocationManager.requestLocationUpdates", "location", {
        provider: provider ? provider.toString() : null,
        minTime: minTime,
        minDistance: minDistance
      });
      return ol.call(this, provider, minTime, minDistance, listener);
    };
  });

  safeHook("TelephonyManager.getDeviceId", function () {
    const TelephonyManager = Java.use("android.telephony.TelephonyManager");
    const ol = TelephonyManager.getDeviceId.overload();
    ol.implementation = function () {
      logEvent("TelephonyManager.getDeviceId", "device_info", {});
      return ol.call(this);
    };
  });

  safeHook("TelephonyManager.getSubscriberId", function () {
    const TelephonyManager = Java.use("android.telephony.TelephonyManager");
    const ol = TelephonyManager.getSubscriberId.overload();
    ol.implementation = function () {
      logEvent("TelephonyManager.getSubscriberId", "device_info", {});
      return ol.call(this);
    };
  });

  safeHook("TelephonyManager.getSimSerialNumber", function () {
    const TelephonyManager = Java.use("android.telephony.TelephonyManager");
    const ol = TelephonyManager.getSimSerialNumber.overload();
    ol.implementation = function () {
      logEvent("TelephonyManager.getSimSerialNumber", "device_info", {});
      return ol.call(this);
    };
  });

  safeHook("TelephonyManager.getCallState", function () {
    const TelephonyManager = Java.use("android.telephony.TelephonyManager");
    const ol = TelephonyManager.getCallState.overload();
    ol.implementation = function () {
      logEvent("TelephonyManager.getCallState", "telephony", {});
      return ol.call(this);
    };
  });

  safeHook("TelephonyManager.getCallState_subId", function () {
    const TelephonyManager = Java.use("android.telephony.TelephonyManager");
    const ol = TelephonyManager.getCallState.overload("int");
    ol.implementation = function (subId) {
      logEvent("TelephonyManager.getCallState", "telephony", { subId: subId });
      return ol.call(this, subId);
    };
  });

  safeHook("DexClassLoader.<init>", function () {
    const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    const ol = DexClassLoader.$init.overload(
      "java.lang.String",
      "java.lang.String",
      "java.lang.String",
      "java.lang.ClassLoader"
    );
    ol.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
      logEvent("DexClassLoader.<init>", "dynamic_code_loading", {
        dexPath: dexPath ? dexPath.toString() : null,
        optimizedDirectory: optimizedDirectory ? optimizedDirectory.toString() : null
      });
      return ol.call(this, dexPath, optimizedDirectory, librarySearchPath, parent);
    };
  });

  safeHook("PathClassLoader.<init>", function () {
    const PathClassLoader = Java.use("dalvik.system.PathClassLoader");
    const ol = PathClassLoader.$init.overload("java.lang.String", "java.lang.ClassLoader");
    ol.implementation = function (dexPath, parent) {
      logEvent("PathClassLoader.<init>", "dynamic_code_loading", {
        dexPath: dexPath ? dexPath.toString() : null
      });
      return ol.call(this, dexPath, parent);
    };
  });

  safeHook("System.loadLibrary", function () {
    const System = Java.use("java.lang.System");
    const ol = System.loadLibrary.overload("java.lang.String");
    ol.implementation = function (libname) {
      logEvent("System.loadLibrary", "native_code", {
        library: libname ? libname.toString() : null
      });
      return ol.call(this, libname);
    };
  });

  safeHook("Runtime.loadLibrary", function () {
    const Runtime = Java.use("java.lang.Runtime");
    const ol = Runtime.loadLibrary.overload("java.lang.String");
    ol.implementation = function (libname) {
      logEvent("Runtime.loadLibrary", "native_code", {
        library: libname ? libname.toString() : null
      });
      return ol.call(this, libname);
    };
  });

  safeHook("Runtime.load", function () {
    const Runtime = Java.use("java.lang.Runtime");
    const ol = Runtime.load.overload("java.lang.String");
    ol.implementation = function (filename) {
      logEvent("Runtime.load", "native_code", {
        path: filename ? filename.toString() : null
      });
      return ol.call(this, filename);
    };
  });

  safeHook("Cipher.doFinal", function () {
    const Cipher = Java.use("javax.crypto.Cipher");
    const ol = Cipher.doFinal.overload("[B");
    ol.implementation = function (input) {
      logEvent("Cipher.doFinal", "crypto", {
        inputLength: input ? input.length : 0
      });
      return ol.call(this, input);
    };
  });

  safeHook("MessageDigest.getInstance", function () {
    const MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload("java.lang.String").implementation = function (algorithm) {
      logEvent("MessageDigest.getInstance", "crypto", {
        algorithm: algorithm ? algorithm.toString() : null
      });
      return MessageDigest.getInstance.overload("java.lang.String").call(this, algorithm);
    };
  });

  safeHook("MessageDigest.digest", function () {
    const MessageDigest = Java.use("java.security.MessageDigest");
    const ol = MessageDigest.digest.overload();
    ol.implementation = function () {
      logEvent("MessageDigest.digest", "crypto", {});
      return ol.call(this);
    };
  });

  safeHook("okhttp3.RealCall.enqueue", function () {
    const RealCall = Java.use("okhttp3.RealCall");
    const ol = RealCall.enqueue.overload("okhttp3.Callback");
    ol.implementation = function (callback) {
      const req = this.request ? this.request() : null;
      logEvent("okhttp3.RealCall.enqueue", "network", {
        url: req ? req.url().toString() : null,
        method: req ? req.method().toString() : null
      });
      return ol.call(this, callback);
    };
  });

  safeHook("AccountManager.getAccounts", function () {
    const AccountManager = Java.use("android.accounts.AccountManager");
    const ol = AccountManager.getAccounts.overload();
    ol.implementation = function () {
      logEvent("AccountManager.getAccounts", "accounts", {});
      return ol.call(this);
    };
  });

  safeHook("AccountManager.getAccountsByType", function () {
    const AccountManager = Java.use("android.accounts.AccountManager");
    const ol = AccountManager.getAccountsByType.overload("java.lang.String");
    ol.implementation = function (type) {
      logEvent("AccountManager.getAccountsByType", "accounts", {
        type: type ? type.toString() : null
      });
      return ol.call(this, type);
    };
  });

  safeHook("AudioRecord.<init>", function () {
    const AudioRecord = Java.use("android.media.AudioRecord");
    const ol = AudioRecord.$init.overload("int", "int", "int", "int", "int");
    ol.implementation = function (audioSource, sampleRateInHz, channelConfig, audioFormat, bufferSizeInBytes) {
      logEvent("AudioRecord.<init>", "audio", {
        audioSource: audioSource,
        sampleRateInHz: sampleRateInHz
      });
      return ol.call(this, audioSource, sampleRateInHz, channelConfig, audioFormat, bufferSizeInBytes);
    };
  });

  safeHook("MediaRecorder.setAudioSource", function () {
    const MediaRecorder = Java.use("android.media.MediaRecorder");
    const ol = MediaRecorder.setAudioSource.overload("int");
    ol.implementation = function (arg) {
      logEvent("MediaRecorder.setAudioSource", "audio", { audioSource: arg });
      return ol.call(this, arg);
    };
  });

  // --- hook_apis v3: ipc_intents, telephony, native_code + storage, database, media, webview ---

  safeHook("SharedPreferencesImpl.getString", function () {
    const SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
    const ol = SharedPreferencesImpl.getString.overload("java.lang.String", "java.lang.String");
    ol.implementation = function (key, defValue) {
      logEvent("SharedPreferences.getString", "storage", { key: key ? key.toString() : null });
      return ol.call(this, key, defValue);
    };
  });

  safeHook("SharedPreferencesImpl.getInt", function () {
    const SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
    const ol = SharedPreferencesImpl.getInt.overload("java.lang.String", "int");
    ol.implementation = function (key, defValue) {
      logEvent("SharedPreferences.getInt", "storage", { key: key ? key.toString() : null });
      return ol.call(this, key, defValue);
    };
  });

  safeHook("SharedPreferencesImpl.EditorImpl.putString", function () {
    const EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    const ol = EditorImpl.putString.overload("java.lang.String", "java.lang.String");
    ol.implementation = function (key, value) {
      logEvent("SharedPreferences.putString", "storage", { key: key ? key.toString() : null });
      return ol.call(this, key, value);
    };
  });

  safeHook("SharedPreferencesImpl.EditorImpl.apply", function () {
    const EditorImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
    const ol = EditorImpl.apply.overload();
    ol.implementation = function () {
      logEvent("SharedPreferences.apply", "storage", {});
      return ol.call(this);
    };
  });

  safeHook("SQLiteDatabase.rawQuery", function () {
    const SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    const ol = SQLiteDatabase.rawQuery.overload("java.lang.String", "[Ljava.lang.String;");
    ol.implementation = function (sql, selectionArgs) {
      logEvent("SQLiteDatabase.rawQuery", "database", {
        sql: sql ? sql.toString().substring(0, 200) : null
      });
      return ol.call(this, sql, selectionArgs);
    };
  });

  safeHook("SQLiteDatabase.execSQL", function () {
    const SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    const ol = SQLiteDatabase.execSQL.overload("java.lang.String");
    ol.implementation = function (sql) {
      logEvent("SQLiteDatabase.execSQL", "database", {
        sql: sql ? sql.toString().substring(0, 200) : null
      });
      return ol.call(this, sql);
    };
  });

  safeHook("SQLiteDatabase.insert", function () {
    const SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    const ol = SQLiteDatabase.insert.overload(
      "java.lang.String",
      "java.lang.String",
      "android.content.ContentValues"
    );
    ol.implementation = function (table, nullColumnHack, values) {
      logEvent("SQLiteDatabase.insert", "database", {
        table: table ? table.toString() : null
      });
      return ol.call(this, table, nullColumnHack, values);
    };
  });

  safeHook("MediaPlayer.setDataSource", function () {
    const MediaPlayer = Java.use("android.media.MediaPlayer");
    const ol = MediaPlayer.setDataSource.overload("java.lang.String");
    ol.implementation = function (path) {
      logEvent("MediaPlayer.setDataSource", "media", { path: path ? path.toString() : null });
      return ol.call(this, path);
    };
  });

  safeHook("MediaPlayer.setDataSource_uri", function () {
    const MediaPlayer = Java.use("android.media.MediaPlayer");
    const ol = MediaPlayer.setDataSource.overload(
      "android.content.Context",
      "android.net.Uri"
    );
    ol.implementation = function (context, uri) {
      logEvent("MediaPlayer.setDataSource", "media", { uri: uri ? uri.toString() : null });
      return ol.call(this, context, uri);
    };
  });

  safeHook("MediaPlayer.start", function () {
    const MediaPlayer = Java.use("android.media.MediaPlayer");
    const ol = MediaPlayer.start.overload();
    ol.implementation = function () {
      logEvent("MediaPlayer.start", "media", {});
      return ol.call(this);
    };
  });

  safeHook("MediaPlayer.prepare", function () {
    const MediaPlayer = Java.use("android.media.MediaPlayer");
    const ol = MediaPlayer.prepare.overload();
    ol.implementation = function () {
      logEvent("MediaPlayer.prepare", "media", {});
      return ol.call(this);
    };
  });

  safeHook("ContextWrapper.startActivity", function () {
    const ContextWrapper = Java.use("android.content.ContextWrapper");
    const ol = ContextWrapper.startActivity.overload("android.content.Intent");
    ol.implementation = function (intent) {
      const summary = summarizeIntent(intent);
      logEvent("Context.startActivity", "ipc_intents", summary);
      logEvent("Context.startActivity", "navigation", { target: summary.target });
      return ol.call(this, intent);
    };
  });

  safeHook("ContextWrapper.sendBroadcast", function () {
    const ContextWrapper = Java.use("android.content.ContextWrapper");
    const ol = ContextWrapper.sendBroadcast.overload("android.content.Intent");
    ol.implementation = function (intent) {
      logEvent("Context.sendBroadcast", "ipc_intents", summarizeIntent(intent));
      return ol.call(this, intent);
    };
  });

  safeHook("ContextWrapper.sendBroadcast_permission", function () {
    const ContextWrapper = Java.use("android.content.ContextWrapper");
    const ol = ContextWrapper.sendBroadcast.overload(
      "android.content.Intent",
      "java.lang.String"
    );
    ol.implementation = function (intent, receiverPermission) {
      const args = summarizeIntent(intent);
      args.receiverPermission = receiverPermission ? receiverPermission.toString() : null;
      logEvent("Context.sendBroadcast", "ipc_intents", args);
      return ol.call(this, intent, receiverPermission);
    };
  });

  safeHook("ContextWrapper.startService", function () {
    const ContextWrapper = Java.use("android.content.ContextWrapper");
    const ol = ContextWrapper.startService.overload("android.content.Intent");
    ol.implementation = function (intent) {
      logEvent("Context.startService", "ipc_intents", summarizeIntent(intent));
      return ol.call(this, intent);
    };
  });

  safeHook("ContextWrapper.bindService", function () {
    const ContextWrapper = Java.use("android.content.ContextWrapper");
    const ol = ContextWrapper.bindService.overload(
      "android.content.Intent",
      "android.content.ServiceConnection",
      "int"
    );
    ol.implementation = function (intent, conn, flags) {
      const args = summarizeIntent(intent);
      args.flags = flags;
      logEvent("Context.bindService", "ipc_intents", args);
      return ol.call(this, intent, conn, flags);
    };
  });

  safeHook("WebView.loadUrl", function () {
    const WebView = Java.use("android.webkit.WebView");
    const ol = WebView.loadUrl.overload("java.lang.String");
    ol.implementation = function (url) {
      logEvent("WebView.loadUrl", "webview", { url: url ? url.toString() : null });
      return ol.call(this, url);
    };
  });

  safeHook("NotificationManager.notify", function () {
    const NotificationManager = Java.use("android.app.NotificationManager");
    const ol = NotificationManager.notify.overload("int", "android.app.Notification");
    ol.implementation = function (id, notification) {
      logEvent("NotificationManager.notify", "notifications", { id: id });
      return ol.call(this, id, notification);
    };
  });

  safeHook("NotificationManager.notify_tag", function () {
    const NotificationManager = Java.use("android.app.NotificationManager");
    const ol = NotificationManager.notify.overload(
      "java.lang.String",
      "int",
      "android.app.Notification"
    );
    ol.implementation = function (tag, id, notification) {
      logEvent("NotificationManager.notify", "notifications", {
        tag: tag ? tag.toString() : null,
        id: id
      });
      return ol.call(this, tag, id, notification);
    };
  });

  safeHook("NotificationManager.notifyAsUser", function () {
    const NotificationManager = Java.use("android.app.NotificationManager");
    const ol = NotificationManager.notifyAsUser.overload(
      "java.lang.String",
      "int",
      "android.app.Notification",
      "android.os.UserHandle"
    );
    ol.implementation = function (tag, id, notification, user) {
      logEvent("NotificationManager.notifyAsUser", "notifications", {
        tag: tag ? tag.toString() : null,
        id: id
      });
      return ol.call(this, tag, id, notification, user);
    };
  });

  safeHook("Socket.connect", function () {
    const Socket = Java.use("java.net.Socket");
    const ol = Socket.connect.overload("java.net.SocketAddress", "int");
    ol.implementation = function (endpoint, timeout) {
      logEvent("Socket.connect", "network", {
        endpoint: endpoint ? endpoint.toString() : null
      });
      return ol.call(this, endpoint, timeout);
    };
  });

  safeHook("AssetManager.open", function () {
    const AssetManager = Java.use("android.content.res.AssetManager");
    const ol = AssetManager.open.overload("java.lang.String", "int");
    ol.implementation = function (fileName, accessMode) {
      logEvent("AssetManager.open", "file_io", {
        path: fileName ? fileName.toString() : null
      });
      return ol.call(this, fileName, accessMode);
    };
  });

  safeHook("retrofit2.OkHttpCall.execute", function () {
    const OkHttpCall = Java.use("retrofit2.OkHttpCall");
    const ol = OkHttpCall.execute.overload();
    ol.implementation = function () {
      let url = null;
      let method = null;
      try {
        const req = this.request();
        if (req) {
          url = req.url().toString();
          method = req.method().toString();
        }
      } catch (e) {
        url = "<unavailable>";
      }
      logEvent("retrofit2.OkHttpCall.execute", "network", { url: url, method: method });
      return ol.call(this);
    };
  });

  safeHook("volley.RequestQueue.add", function () {
    const RequestQueue = Java.use("com.android.volley.RequestQueue");
    const ol = RequestQueue.add.overload("com.android.volley.Request");
    ol.implementation = function (request) {
      let url = null;
      try {
        url = request ? request.getUrl() : null;
      } catch (e) {
        url = "<unavailable>";
      }
      logEvent("volley.RequestQueue.add", "network", { url: url ? url.toString() : null });
      return ol.call(this, request);
    };
  });
});

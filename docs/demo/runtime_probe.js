// HardenInspector optional runtime review probe.
//
// This Frida script is a minimal future-extension prototype: it records API
// observations that can be compared with static HardenInspector findings. It
// does not bypass checks, patch return values, dump payloads, or change app
// behavior.

Java.perform(function () {
  const System = Java.use("java.lang.System");
  System.getProperty.overload("java.lang.String").implementation = function (key) {
    const value = this.getProperty(key);
    send({
      hook: "System.getProperty",
      key: String(key),
      value: String(value)
    });
    return value;
  };

  const Debug = Java.use("android.os.Debug");
  Debug.isDebuggerConnected.implementation = function () {
    const value = this.isDebuggerConnected();
    send({
      hook: "Debug.isDebuggerConnected",
      value: value
    });
    return value;
  };

  const ClassLoader = Java.use("java.lang.ClassLoader");
  ClassLoader.loadClass.overload("java.lang.String").implementation = function (name) {
    const loaded = this.loadClass(name);
    send({
      hook: "ClassLoader.loadClass",
      class_name: String(name)
    });
    return loaded;
  };
});

function attachNativeLoader(name) {
  const address = Module.findExportByName(null, name);
  if (!address) return;
  Interceptor.attach(address, {
    onEnter(args) {
      const path = args[0].isNull() ? "" : args[0].readCString();
      send({
        hook: name,
        path: path
      });
    }
  });
}

attachNativeLoader("dlopen");
attachNativeLoader("android_dlopen_ext");

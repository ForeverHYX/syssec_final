# 检测规则说明

HardenInspector 的规则是解释型静态规则。规则命中表示“存在相关静态证据”，不表示 APK 一定恶意。

## 加壳类规则

### `packer.known_library`

检测 APK 中是否存在常见加固/壳相关 Native 库名。

当前信号包括：

- `libjiagu.so`
- `libjiagu_art.so`
- `libsecexe.so`
- `libsecmain.so`
- `libDexHelper.so`
- `libshell.so`
- `libprotectClass.so`

证据位置：APK 文件路径，例如 `lib/arm64-v8a/libjiagu.so`。

### `packer.stub_application`

检测 Manifest 字符串中是否出现壳入口类或相关包名前缀。

当前信号包括：

- `StubApp`
- `com.qihoo`
- `secneo`
- `bangcle`
- `ijiami`
- `ali.protect`

证据位置：`AndroidManifest.xml`。

### `packer.high_entropy_payload`

检测 `assets/` 中是否存在高熵二进制 payload。

当前阈值：

- 文件大小不少于 128 bytes；
- Shannon entropy 不低于 7.5。

该规则置信度为 medium，因为压缩资源、模型文件或媒体文件也可能高熵。

### `packer.dynamic_code_loading`

检测动态加载相关字符串。

当前信号包括：

- `DexClassLoader`
- `PathClassLoader`
- `BaseDexClassLoader`
- `InMemoryDexClassLoader`
- `loadDex`

该规则同时可能出现在正常插件化框架中，因此需要结合其他证据解释。

## 混淆类规则

### `obfuscation.short_identifiers`

统计 DEX type descriptor 中简单类名长度。当至少 3 个类名存在，且 60% 以上的简单类名长度不超过 2 时命中。

示例：

- `La/a;`
- `Lb/b;`
- `Lc/c;`

该规则用于识别 ProGuard/R8/商业混淆器常见的标识符重命名现象。

### `obfuscation.reflection`

检测反射相关字符串或方法名。

当前信号包括：

- `java.lang.reflect.Method`
- `java/lang/reflect/Method`
- `Method.invoke`
- DEX 方法名 `invoke`

反射可能是正常框架行为，也可能用于隐藏真实调用目标，因此规则置信度为 medium。

### `obfuscation.control_flow_density`

统计 DEX code item 中控制流相关 opcode 的密度。

当前纳入统计的信号包括：

- `if-*` 条件分支；
- `goto`、`goto/16`、`goto/32`；
- `packed-switch`、`sparse-switch`；
- `throw`。

当前阈值：

- 指令数不少于 8；
- 控制流 opcode 数不少于 5；
- 控制流密度不低于 0.42。

该规则不是完整 CFG，也不声称还原真实执行路径。它用于提示可能存在控制流平坦化、跳转扰动或异常控制流混淆，报告中会输出 density、if/goto/switch/throw 计数和 DEX 文件位置。

## 环境检测类规则

### `environment.system_properties`

检测模拟器或设备指纹相关 system property。

当前信号包括：

- `ro.kernel.qemu`
- `ro.build.fingerprint`
- `ro.product.model`
- `ro.hardware`
- `goldfish`
- `ranchu`
- `genymotion`

### `environment.debugger_probe`

检测调试器探测相关证据。

当前信号包括：

- `isDebuggerConnected`
- `/proc/self/status`
- `TracerPid`
- `ptrace`

### `environment.instrumentation_probe`

检测动态插桩框架或进程映射扫描相关证据。

当前信号包括：

- `frida`
- `xposed`
- `substrate`
- `/proc/self/maps`
- `libfrida`

## Native 类规则

### `native.jni_entrypoint`

检测 Native 字符串中是否出现 `JNI_OnLoad`。

它说明 APK 存在 Java 到 Native 的执行路径。该规则本身不代表加壳，但在和壳库名、动态加载、环境检测证据同时出现时，可以增强对加固结构的解释。

## 误报处理原则

规则输出保留 `confidence`，并且报告完整 evidence。展示和分析时应按证据链解释，而不是只看标签。

典型误报来源：

- 正常插件化框架也使用 `DexClassLoader`；
- 正常调试/诊断代码可能包含 `/proc/self/status`；
- 大型资源文件可能高熵；
- 合法保护场景也可能使用加壳或混淆。

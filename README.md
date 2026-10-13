# patched-frida-build

在 GitHub Actions 云端编译**去反检测特征**的 frida-server(Android arm64),用于对抗加固 App 的反-frida 检测。

## 用法

1. 在 GitHub 网页新建一个**空仓库**(Public 即可,免费 Actions 额度足够)。
2. 把本目录推上去(见下)。
3. 进仓库 **Settings → Actions → General**,确认 **Allow all actions and reusable workflows** 已勾选。
4. 进 **Actions** 标签 → 左侧选 **build-patched-frida** → **Run workflow**,
   `frida_version` 填 `16.2.2`(必须和本机 frida 一致)→ 绿色 Run。
5. 等约 60–90 分钟,编译完成后在该次 run 页面底部 **Artifacts** 下载
   `frida-server-patched-android-arm64`。
6. 把解压出的 `frida-server-patched-16-android-arm64` 发回来部署。

## 推送命令

```bash
cd frida-build
git init
git add -A
git commit -m "patched frida build: anti-detection source patch + CI"
git branch -M main
git remote add origin https://github.com/<你的用户名>/<仓库名>.git
git push -u origin main
```

## patch 做了什么(`patch.sh`)

源码级替换,client 和 server 从同一份源码编译,socket/D-Bus 端点名两端保持一致:

- **线程名** `gum-js-loop` / `pool-frida` / `frida-gum` → 去特征(对抗 `/proc/<pid>/task/*/comm` 扫描)
- **`re.frida.*`** → `re.axcorp.*`(D-Bus well-known 名 + abstract unix socket 名,对抗 `/proc/<pid>/net/unix` 扫描)
- **`frida-pipe`** → `axcorp-pipe`

**保留不动**:`frida:rpc`(client/server 握手协议魔数)、`frida_agent_main`(导出符号)。

## 为什么要源码编译

纯二进制 patch 能改线程名/进程名/端口,但 socket 与 D-Bus **端点名必须 client 和 server 一致**,
而官方 client(`_frida.pyd`)是编译死的二进制改不了。源码编译同时产出改过的 client 库和 server,
两端一致,才能既隐身又正常通信。

## 版本说明

锁定 **16.2.2**:frida 17.x 在目标测试设备(Pixel 2 / Android 11 AOSP)上有
`sigchain validate_signal` 断言崩溃,无法运行;16.2.2 实测可用。

# Aptelly compatibility apps

[Downloads](https://github.com/AptellyTV/compat-apps/releases) · [Application catalog](catalog.json) · [License](LICENSE)

This is the shared download hub for independently maintained Android TV compatibility applications. Each application has its own package identity, versions and signing certificate.

Install an application offered for your television by Aptelly, then open its TV launcher entry. Sign into your own service account when the application requires one. Integrated compatibility fixes are included in the download; users do not need developer tools or separate patch ZIP files.

Each release includes one signed APK, its checksum, a signed version manifest, the public signing certificate, the corresponding source package and third-party notices. Versioned downloads remain available for verification and rollback. Stable and beta releases are tracked separately for each application in `catalog.json`; the repository-wide “latest release” is not an application update feed.

Application compatibility depends on the tested hardware and software profile. Aptelly presents releases supported by the matching profile.

## 中文

这里统一提供适视维护的 Android TV 兼容应用。每个应用独立维护包名、版本和签名，修复预先集成在安装包中。用户通过适视安装适配版本，打开桌面入口并登录自己的账号即可使用，无需开发工具或手动导入补丁。

同一仓库可以容纳多个应用。每个发布版本包含安装包、校验文件、签名版本清单、公开签名证书、对应源码和第三方声明。稳定版和测试版按应用分别管理。

## License

The distribution tooling is licensed under [Apache License 2.0](LICENSE). Application source packages and bundled components retain their own licenses and notices. Aptelly names and trademarks are not granted by the software license. These are independently maintained compatibility applications.

# 3105 — configurado (versões + worse_query)

## Já está no projeto

- SupportPolicy com gates: 15/16 jailbreak, 17/18 kernel, 26.0 kernel, 26.0–26.7.2 + 27.0–27.2.1 + 27.3b1 `24C5037i` worse_query
- KernelExploit: tenta worse_query primeiro, depois kernel
- FFWorseQuery + vendor/worse_query na pasta (sincronizada pelo Xcode)
- Bridging header com `#import "helpers/FFWorseQuery.h"`
- Info.plist: MinimumOSVersion 15.0 + FFWorseQueryAppGroup
- Entitlements com App Group
- project.pbxproj + scheme **3105** (deployment 15.0)
- Settings com ranges atualizadas

## Única coisa no Mac

1. Abrir `ThreeOneOSFive.xcodeproj`
2. Signing & Capabilities → teu Team + App Groups (cria `group.com.seudominio.3105`)
3. Trocar o placeholder `group.com.yourteam.threeoneosfive` em:
   - `ThreeOneOSFive/ThreeOneOSFive.entitlements`
   - `ThreeOneOSFive/Info.plist` → `FFWorseQueryAppGroup`
4. Build scheme **3105**

Sem App Group real no provisioning, worse_query não concede path em 26/27.

## Backends

| iOS | Backend |
|-----|---------|
| 15–16 | jailbreak path |
| 17–18.7 | kernel 3105 |
| 26.0 | kernel ou worse_query |
| 26.1–26.7.2 | worse_query |
| 27.0–27.2.1 | worse_query |
| 27.3 Beta1 build 24C5037i | worse_query |

# Stem Password Generator v1.0 Release Checklist

## ✔ Ready items

- Application name: `Stem Password Generator`
- Assembly name: `StemPasswordGenerator`
- Executable name inside MSIX: `StemPasswordGenerator.exe`
- Package identity name: `Stem.PasswordGenerator`
- Package version: `1.0.0.0`
- Assembly version: `1.0.0.0`
- File version: `1.0.0.0`
- Product version: `1.0.0`
- Package display name: `Stem Password Generator`
- Publisher display name: `Stem`
- App short name: `Stem Password`
- App description: `Generate secure passwords locally on Windows.`
- Target framework: `.NET 8`
- UI framework: `WinUI 3`
- Windows App SDK package: `Microsoft.WindowsAppSDK 2.2.0`
- Release architecture generated: `x64`
- MSIX manifest includes one application entry.
- MSIX package contains `AppxManifest.xml`, `AppxBlockMap.xml`, and `[Content_Types].xml`.
- No Internet capability is declared.
- No personal file library capability is declared.
- No account/login capability is declared.
- No broad file system capability is declared.
- Preferences are stored locally with `ApplicationData.LocalSettings`.
- Clipboard access is only used when the user clicks `Copy`.
- Solution build succeeds with 0 warnings and 0 errors.
- MSIX generation succeeds.

## ⚠ Remaining manual tasks

- Reserve or confirm the Microsoft Store app identity in Partner Center.
- Replace `Publisher="CN=Stem"` with the exact publisher identity from Partner Center before final Store submission if it differs.
- Confirm `PublisherDisplayName="Stem"` matches the public publisher name in Partner Center.
- Verify the final production artwork in Partner Center previews before submission.
- Confirm whether Partner Center submission should use the development-signed MSIX, a Store upload package, or Partner Center-managed signing for the final public submission.
- Run Windows App Certification Kit in an elevated active user session and save the final report.
- Install the missing packaging prerequisite that provides `mspdbcmf.exe` if symbol package generation is required.
- Complete Store listing text, category, age rating, pricing, markets, support contact, and privacy policy fields in Partner Center.

## 📦 Package location

Generated MSIX:

```text
StemPasswordGenerator\AppPackages\StemPasswordGenerator_1.0.0.0_x64_Test\StemPasswordGenerator_1.0.0.0_x64.msix
```

Absolute path:

```text
C:\Users\enman\Desktop\New folder\generador de contraseñas\StemPasswordGenerator\AppPackages\StemPasswordGenerator_1.0.0.0_x64_Test\StemPasswordGenerator_1.0.0.0_x64.msix
```

Package size:

```text
58.69 MB
```

Signing status:

```text
Valid development signature
```

Development certificate:

```text
Subject: CN=Stem
Thumbprint: E03E007E64CF47D289D3E65AD4EC8D5935C94A6B
Public certificate: StemPasswordGenerator\AppPackages\StemPasswordGenerator_1.0.0.0_x64_Test\StemPasswordGenerator_1.0.0.0_x64.cer
Private certificate: C:\Users\enman\AppData\Local\StemPasswordGenerator\Certificates\StemPasswordGenerator_Development_CodeSigning.pfx
```

The private certificate is stored outside the source tree and `*.pfx` is ignored by `.gitignore`.

## 🖼 Required screenshots

Minimum Store listing requirement:

- At least 1 desktop screenshot.
- PNG format.
- 1366 x 768 pixels or larger for Desktop.
- Maximum file size: 50 MB per screenshot.

Recommended:

- 4 desktop screenshots.
- Use 3840 x 2160 for high-quality Store presentation when possible.
- Capture both light and dark theme if submitting multiple screenshots.
- Show the main app window with a generated password and visible strength bar.

## 🎨 Required Store images

Package manifest image assets currently referenced:

| Asset | Size | Status |
| --- | ---: | --- |
| `Assets\StoreLogo.png` | 50 x 50 | Provided logo |
| `Assets\Square44x44Logo.png` | 44 x 44 | Provided logo |
| `Assets\Square150x150Logo.png` | 150 x 150 | Provided logo |
| `Assets\Wide310x150Logo.png` | 310 x 150 | Provided logo |
| `Assets\SplashScreen.png` | 620 x 300 | Provided logo |

Before submission:

- Keep filenames or update `Package.appxmanifest` accordingly if artwork changes later.
- Verify each referenced image exists after packaging.
- Add optional Store promotional images in Partner Center if desired.

## 📝 Store description needed

Suggested short description:

```text
Generate secure passwords locally on Windows.
```

Long description still needed in Partner Center. It should mention:

- Passwords are generated locally.
- No Internet connection is required.
- No account is required.
- Preferences are stored on the device.
- The app supports configurable length, character types, ambiguous character avoidance, copy to clipboard, and visual strength feedback.

## 🌐 Privacy Policy URL needed

The app does not declare Internet access and does not collect personal data based on the current code review.

Still provide a privacy policy URL for Store readiness. Suggested policy content:

- No analytics.
- No telemetry.
- No account login.
- No Internet communication.
- No collection or sale of personal data.
- Preferences remain on the user's device.
- Clipboard is used only when the user selects `Copy`.

## 🚀 Final publication steps

1. Reserve the app name in Partner Center.
2. Confirm the package identity name and publisher match Partner Center.
3. Replace all placeholder icons and splash assets.
4. Rebuild the solution:

   ```powershell
   dotnet build .\StemPasswordGenerator.slnx
   ```

5. Regenerate the MSIX:

   ```powershell
   dotnet publish .\StemPasswordGenerator\StemPasswordGenerator.csproj -p:PublishProfile=win-x64
   ```

6. Run Windows App Certification Kit from an elevated active user session.
7. Capture Store screenshots.
8. Create or update the Store listing in Partner Center.
9. Add privacy policy URL and support contact.
10. Upload the final package.
11. Complete age rating and pricing/availability.
12. Submit for certification.

## Validation performed

Build:

```text
dotnet build .\StemPasswordGenerator.slnx
Build succeeded.
0 warnings.
0 errors.
```

MSIX generation:

```text
dotnet publish .\StemPasswordGenerator\StemPasswordGenerator.csproj -p:PublishProfile=win-x64
MSIX generated successfully.
```

Remaining publish warning:

```text
Path to mspdbcmf.exe could not be found. A symbols package will not be generated.
```

WACK note:

- `appcert.exe` exists at `C:\Program Files (x86)\Windows Kits\10\App Certification Kit\appcert.exe`.
- Command-line invocation did not create a report in this shell session.
- Microsoft documents that WACK command-line validation should be run in an elevated active user session.

## Official references

- Windows App Certification Kit: https://learn.microsoft.com/en-us/windows/uwp/debug-test-perf/windows-app-certification-kit
- Windows App Certification Kit tests: https://learn.microsoft.com/en-us/windows/uwp/debug-test-perf/windows-app-certification-kit-tests
- MSIX app certification process: https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/app-certification-process
- Store listing info for MSIX apps: https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/add-and-edit-store-listing-info
- Screenshots and images for MSIX apps: https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/screenshots-and-images
- `uap:VisualElements` manifest reference: https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-uap-visualelements
